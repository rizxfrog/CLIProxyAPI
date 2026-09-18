#!/usr/bin/env bash
# fingerprint-client.sh — measure a CLI/desktop binary's TLS fingerprint.
#
# Runs <command> and reports the JA3/JA4-relevant ClientHello fields it produced,
# using up to three independent, privilege-free techniques (first one that yields
# data wins; the others are tried automatically):
#
#   1. CONNECT-proxy capture   (connect-proxy.mjs) — best fidelity, no MITM.
#   2. strace write capture    (extract-hello.py) — when the client ignores proxies.
#   3. Chromium net-log        (--log-net-log)    — negotiated params only.
#
# Usage:
#   ./fingerprint-client.sh -- <command> [args...]
#   ./fingerprint-client.sh --timeout 40 -- <command> [args...]
#
# Environment knobs:
#   FP_OUT        output dir                     (default /tmp/fp)
#   FP_PROXY_PORT CONNECT proxy port             (default 8899)
#   FP_PROXY_ENV  space list of proxy env vars to set
#                 (default "HTTPS_PROXY HTTP_PROXY https_proxy http_proxy")
#   FP_NO_PROXY   set to 1 to skip the proxy technique
#   FP_NO_STRACE  set to 1 to skip the strace technique
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMEOUT=30
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

if [[ $# -eq 0 ]]; then
  echo "usage: $0 [--timeout SECS] -- <command> [args...]" >&2
  exit 2
fi

OUT="${FP_OUT:-/tmp/fp}"
PROXY_PORT="${FP_PROXY_PORT:-8899}"
PROXY_ENV="${FP_PROXY_ENV:-HTTPS_PROXY HTTP_PROXY https_proxy http_proxy}"
mkdir -p "$OUT"

proxy_log="$OUT/proxy.log"
strace_log="$OUT/strace.txt"
netlog="$OUT/netlog.json"
summary="$OUT/summary.json"

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Technique 1: CONNECT proxy
# ---------------------------------------------------------------------------
capture_proxy() {
  [[ "${FP_NO_PROXY:-0}" == "1" ]] && return 1
  have node || return 1
  : >"$proxy_log"

  PROXY_PORT="$PROXY_PORT" PROXY_LOG="$proxy_log" \
    node "$HERE/connect-proxy.mjs" >"$OUT/proxy.stdout" 2>"$OUT/proxy.stderr" &
  local proxy_pid=$!
  sleep 1.2
  if ! kill -0 "$proxy_pid" 2>/dev/null; then
    echo "  [proxy] failed to start (see $OUT/proxy.stderr)" >&2
    return 1
  fi

  local -a envs=()
  for v in $PROXY_ENV; do envs+=("$v=http://127.0.0.1:$PROXY_PORT"); done
  env "${envs[@]}" timeout "$TIMEOUT" "$@" >"$OUT/app.stdout" 2>"$OUT/app.stderr" || true

  sleep 0.5
  kill "$proxy_pid" 2>/dev/null || true
  wait "$proxy_pid" 2>/dev/null || true

  grep -q '"clienthello"' "$proxy_log" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Technique 2: strace write capture
# ---------------------------------------------------------------------------
capture_strace() {
  [[ "${FP_NO_STRACE:-0}" == "1" ]] && return 1
  have strace || return 1
  : >"$strace_log"
  strace -f -qq -e trace=write,writev,sendto,sendmsg -s 8192 -xx \
    -o "$strace_log" timeout "$TIMEOUT" "$@" >"$OUT/app.strace.stdout" 2>&1 || true
  grep -q '\\x16\\x03' "$strace_log" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
report() {
  local src="$1"
  python3 - "$src" "$summary" <<'PY'
import json, sys
src, summary = sys.argv[1], sys.argv[2]
hellos = {}
with open(src) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get('kind') == 'clienthello' or 'ja3' in d:
            hellos.setdefault((d.get('ja3'), d.get('host')), d)

print(f"  {len(hellos)} unique ClientHello(s)")
for (ja3, host), d in hellos.items():
    alpn = ','.join(d.get('alpn') or []) or '(none)'
    print(f"    JA3 {ja3}  host={host}  sni={d.get('sni')!r}")
    print(f"        ALPN={alpn}  versions={d.get('supported_versions') or d.get('sv')}")
    print(f"        ja3str={d.get('ja3str')}")
    if d.get('grease') is not None:
        print(f"        grease={d.get('grease')}")
with open(summary, 'w') as fh:
    json.dump(list(hellos.values()), fh, indent=2)
PY
}

echo "== fingerprinting: $*"
echo "   outdir : $OUT"

RAW="$OUT/hello.jsonl"
: >"$RAW"

if capture_proxy "$@"; then
  echo "   technique: CONNECT proxy (raw ClientHello)"
  cp "$proxy_log" "$RAW"
elif capture_strace "$@"; then
  echo "   technique: strace write capture (raw ClientHello)"
  if have python3; then
    if python3 "$HERE/extract-hello.py" "$strace_log" >"$OUT/hello-from-strace.json"; then
      python3 - "$OUT/hello-from-strace.json" "$RAW" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src) as fh:
    data = json.load(fh)
with open(dst, 'w') as fh:
    for d in data:
        d.setdefault('kind', 'clienthello')
        d.setdefault('host', d.get('sni'))
        fh.write(json.dumps(d) + '\n')
PY
    fi
  fi
else
  echo "   no ClientHello captured by proxy or strace." >&2
  echo "   - the client may ignore proxy env vars; try --proxy-server / a system-wide proxy" >&2
  echo "   - or it may be statically linked and use io_uring/sendfile (add more syscalls to trace)" >&2
  exit 1
fi

if [[ -s "$RAW" ]]; then
  report "$RAW"
  echo "== done (summary: $summary)"
fi
