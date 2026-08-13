#!/bin/bash
#
# LinnemanLabs - find unloaded services to activate from confined domain
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# Find systemd services that are not currently loaded that a confined domain can reach.
# Used when creating new systemd unit files that we activate through .wants dependency
# symlinks, overriding existing systemd units or doing the environment poisoning technique.
#
# examples:
# ./cold-activatable-services.sh
# ./cold-activatable-services.sh bluetooth_t
#
set -u
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
# prevent accidental awk '' that hangs forever inheriting tty
exec </dev/null
# check for reachability from specific domain or just all services
W=${1:-}
# work in tmpdir, cleanup on exit
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# currently-loaded unit names (a unit not in this list is unloaded)
echo "[*] enumerating systemd loaded units"
systemctl list-units --all --type=service --no-legend 2>/dev/null | awk '{gsub(/●/,""); print $1}' | tr -d ' ' | sort -u > "$TMP/loaded"
echo "[+] excluding $(wc -l "$TMP/loaded" | cut -d ' '  -f 1) loaded units"

# find all domains W can reach: dbus:send_msg to target (expands target attributes to member types)
if [ -n "$W" ]; then
  echo "[*] enumerating all domains ${W} can reach (may take a second)"
  attrs=$(seinfo -a 2>/dev/null | sed -nE 's/^[[:space:]]+([A-Za-z0-9_]+)$/\1/p')
  sesearch -A -s "$W" -c dbus -p send_msg 2>/dev/null \
    | sed -nE 's/^allow +[A-Za-z0-9_]+ +([A-Za-z0-9_]+):dbus.*/\1/p' | sort -u \
    | while read -r t; do
        if grep -qxF "$t" <<<"$attrs"; then seinfo -a "$t" -x 2>/dev/null | grep -oE '[a-z0-9_]+_t'
        else echo "$t"; fi
      done | sort -u > "$TMP/reach"
  echo "[+] found $(wc -l "$TMP/reach" | cut -d ' ' -f 1) reachable domains"
  # landing-domain map in one sesearch: exectype -> domain
  sesearch -T -s init_t -c process 2>/dev/null \
    | sed -nE 's/^[[:space:]]*type_transition +init_t +([A-Za-z0-9_]+):process +([A-Za-z0-9_]+);.*/\1 \2/p' \
    | sort -u > "$TMP/trans"
  echo "[+] found $(wc -l "$TMP/trans" | cut -d ' ' -f 1) transitions"
fi

echo "[*] checking each dbus-activated service"
printf "%-34s %-42s %-6s %s\n" "DBUS NAME" "UNIT" "STATE" "${W:+REACHABLE-BY-$W}"
# loop through all dbus-activated service files
for f in /usr/share/dbus-1/system-services/*.service; do
  n=$(basename "$f" .service)
  svc=$(sed -nE 's/^SystemdService=//p' "$f" | tr -d '[:space:]'); [ -z "$svc" ] && continue
  # resolve alias to the real unit name for the cold check
  real="$svc"; ruf="/usr/lib/systemd/system/$svc"; [ -L "$ruf" ] && real=$(basename "$(readlink -f "$ruf")")
  # if loaded then it is not eligible
  grep -qxF "$svc" "$TMP/loaded" && continue
  grep -qxF "$real" "$TMP/loaded" && continue
  reach=""
  if [ -n "$W" ]; then
    # find the unit fragment (alias -> real). may be absent (dbus alias to an un-enabled/uninstalled unit)
    uf="/usr/lib/systemd/system/$svc"; [ -L "$uf" ] && uf=$(readlink -f "$uf")
    [ -f "$uf" ] || uf=$(ls "/usr/lib/systemd/system/$real" "/etc/systemd/system/$svc" "/run/systemd/system/$svc" 2>/dev/null | head -1)
    exe=""
    [ -n "$uf" ] && [ -f "$uf" ] && \
      exe=$(awk -F= '/^ExecStart=/{print $2; exit}' "$uf" | awk '{print $1}' | sed 's/^[-@+!:]*//')
    if [ -n "$exe" ] && [ -e "$exe" ]; then
      # actual on-disk label (what the type_transition fires on), instant vs matchpathcon
      lbl=$(ls -Zd "$exe" 2>/dev/null | awk '{print $1}' | cut -d: -f3)
      dom=$(awk -v l="$lbl" '$1==l{print $2; exit}' "$TMP/trans"); [ -z "$dom" ] && dom="unconfined_service_t"
      grep -qxF "$dom" "$TMP/reach" && reach="yes($dom)" || reach="no($dom)"
    else
      # fragment/binary unresolvable -> reachability undetermined
      reach="n/a(unit-absent)"
    fi
  fi
  printf "%-34s %-42s %-6s %s\n" "$n" "$svc" "COLD" "$reach"
done | sort -k4
