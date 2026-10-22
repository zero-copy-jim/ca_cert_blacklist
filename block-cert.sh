#!/usr/bin/env bash
# block-emudhra.sh - distrust the roots behind the compromised eMudhra intermediates
# (Red Hat RHSB-2026-012 mitigation) on RHEL 7, 8, 9 and 10.
#
# Usage (as root):
#   ./block-emudhra.sh            apply the blocklist, then verify
#   ./block-emudhra.sh --check    report status only (exit 0 = safe, 2 = still trusted for TLS)
#   ./block-emudhra.sh --undo     remove the blocklist entries
#
# BLOCK_AAA=0 ./block-emudhra.sh  block only emSign ECC Root CA - G3, leave Comodo AAA alone
# Safe to run more than once. Red Hat's ca-certificates update can be installed on top later.

set -euo pipefail

ROOTS=("emSign ECC Root CA - G3")
[[ "${BLOCK_AAA:-1}" == "1" ]] && ROOTS+=("Comodo AAA Services root")

BUNDLE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
MODE="${1:-apply}"

die() { echo "ERROR: $*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "run as root (sudo $0 $*)"; }

blocklist_dir() {
  local d=/etc/pki/ca-trust/source/blocklist          # RHEL 9/10
  [[ -d $d ]] || d=/etc/pki/ca-trust/source/blacklist # RHEL 7/8
  [[ -d $d ]] || die "no blocklist directory under /etc/pki/ca-trust/source"
  echo "$d"
}

# Prints the trust state of a root by label: anchor, distrusted, blacklisted, ... or "absent"
trust_state() {
  trust list | awk -v want="$1" '
    /^pkcs11:/                       { cur = "" }
    $1 == "label:"                   { l = $0; sub(/^[ \t]*label: /, "", l); cur = l }
    $1 == "trust:" && cur == want && !found { st = $2; found = 1 }
    END                              { print (found ? st : "absent") }'
}

# Returns 0 if none of the roots is in the TLS bundle that OpenSSL/curl/Python/Go read
report() {
  local exposed=0 label state inb
  for label in "${ROOTS[@]}"; do
    state=$(trust_state "$label")
    if grep -qxF "# $label" "$BUNDLE" 2>/dev/null; then inb=yes; exposed=1; else inb=no; fi
    printf '  %-26s trust: %-12s in TLS bundle: %s\n' "$label" "$state" "$inb"
  done
  return "$exposed"
}

apply() {
  local dir label f
  dir=$(blocklist_dir)
  for label in "${ROOTS[@]}"; do
    f="$dir/${label// /_}.pem"
    case "$(trust_state "$label")" in
      absent)                 echo "  $label: not in trust store, skipping"; continue ;;
      distrusted|blacklisted) echo "  $label: already distrusted, skipping"; continue ;;
    esac
    trust extract --overwrite --format=pem-bundle \
      --filter="pkcs11:object=${label// /%20};type=cert" "$f"
    grep -q 'BEGIN CERTIFICATE' "$f" || { rm -f -- "$f"; die "could not extract '$label'"; }
    echo "  $label: blocked via $f"
  done
  update-ca-trust extract
}

undo() {
  local dir label f
  dir=$(blocklist_dir)
  for label in "${ROOTS[@]}"; do
    f="$dir/${label// /_}.pem"
    if [[ -e $f ]]; then rm -f -- "$f"; echo "  removed $f"; else echo "  $f not present"; fi
  done
  update-ca-trust extract
}

command -v trust >/dev/null || die "'trust' command not found (RHEL 6 has none: install Red Hat's ca-certificates update instead)"

case "$MODE" in
  --check|check)
    echo "Status on $(hostname):"
    if report; then echo "OK: not trusted for TLS"; exit 0
    else echo "EXPOSED: still trusted for TLS (run without --check to block)"; exit 2; fi
    ;;
  --undo|undo)
    need_root "$MODE"
    echo "Removing blocklist entries:"; undo
    echo "Status:"; report || true
    echo "Restart long-running services so they reload the trust store."
    ;;
  apply|--apply)
    need_root
    echo "Blocking on $(hostname):"; apply
    echo "Status:"
    report || die "a root is still present in $BUNDLE"
    echo "Done. Restart long-running services (Java apps, nginx, httpd, proxies) so they reload the trust store."
    ;;
  -h|--help) sed -n '2,12p' "$0" ;;
  *) die "unknown option '$MODE' (use --check, --undo, or no argument)" ;;
esac
