#!/usr/bin/env bash
# Measurements for the choice of the TLS configuration profile (Mozilla 5.7 bundled today, TLSRef 6.0 proposed).
# Every check prints its command, the lines that decide it, and "exit=<code>".
# sslyze exits 1 when a server is not compliant, so the verdict comes from the "tls_curves" lines, not from the exit code.
set -u

HOSTS=(www.cloudflare.com www.google.com www.mozilla.com www.facebook.com)
TLSREF_60=https://data.tlsref.org/guidelines/6.0.json
TLSREF_LATEST=https://data.tlsref.org/guidelines/latest.json
MOZILLA_60=https://ssl-config.mozilla.org/guidelines/6.0.json

srv=
tmp=$(mktemp -d)
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null; rm -rf "$tmp"' EXIT
REPO=$PWD

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}

# $1 = label, $2 = python binary, $3 = target, $4 = directory to run from
scan() {
  local label=$1 py=$2 target=$3 dir=$4
  echo "+ [$label] (cd $dir && $py -m sslyze --mozilla_config=intermediate $target)"
  (cd "$dir" && "$py" -m sslyze --mozilla_config=intermediate "$target") > "$tmp/out.txt" 2>&1
  echo "exit=$?"
  grep -i -E "Supported (Elliptic Curve|Post-Quantum) groups|Supported curves|Rejected curves|COMPLIANCE|compliant|tls_curves|discarding scan|TLS probing failed|Error when running|Traceback" "$tmp/out.txt"
  echo "tls_curves_lines=$(grep -c 'tls_curves' "$tmp/out.txt")"
}

# Does the server accept X25519MLKEM768 when the client offers only this group?
pq_handshake() {
  local host=$1 port=$2 sni=$3
  echo "+ $NASSL_OPENSSL s_client -connect $host:$port -servername $sni -tls1_3 -groups X25519MLKEM768 < /dev/null"
  timeout 20 "$NASSL_OPENSSL" s_client -connect "$host:$port" -servername "$sni" -tls1_3 -groups X25519MLKEM768 < /dev/null > "$tmp/s_client.txt" 2>&1
  echo "exit=$?"
  grep -E "Negotiated TLS1.3 group|^Protocol|alert|handshake failure|errno" "$tmp/s_client.txt" | head -5
}

start_server() {
  local port=$1 groups=$2
  echo "+ $NASSL_OPENSSL s_server -tls1_3 -groups $groups -cert tests/server_certificates/rsa/server-rsa-cert.pem -key tests/server_certificates/rsa/server-rsa-key.pem -accept 127.0.0.1:$port -www"
  "$NASSL_OPENSSL" s_server -tls1_3 -groups "$groups" -cert "$REPO/tests/server_certificates/rsa/server-rsa-cert.pem" \
    -key "$REPO/tests/server_certificates/rsa/server-rsa-key.pem" -accept "127.0.0.1:$port" -www > "$tmp/s_server.log" 2>&1 &
  srv=$!
  for _ in $(seq 50); do grep -q '^ACCEPT' "$tmp/s_server.log" && break; sleep 0.2; done
  grep -q '^ACCEPT' "$tmp/s_server.log" && echo "s_server ready" || { echo "s_server NOT ready"; cat "$tmp/s_server.log"; }
}

stop_server() {
  kill "$srv"
  wait "$srv" 2>/dev/null
  srv=
}

# Checks the same scan results against the bundled 5.7 "intermediate" config and against TLSRef 6.0 "intermediate".
# 6.0 has no ciphers.caddy/ciphers.go, which the current model requires: they are set to empty lists here,
# which is what making them optional would do. The sslyze code is not changed.
cat > "$tmp/check_60.py" <<'EOF'
import json
import sys

from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
from sslyze.mozilla_tls_profile.tls_config_checker import (
    SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER,
    MozillaTlsConfiguration,
    ServerNotCompliantWithTlsConfiguration,
    ServerScanResultIncomplete,
    TlsConfigurationAsJson,
    TlsConfigurationEnum,
    check_server_against_tls_configuration,
)

profile_path, targets = sys.argv[1], sys.argv[2:]
config_60 = json.load(open(profile_path))["configurations"]["intermediate"]
config_60["ciphers"].setdefault("caddy", [])
config_60["ciphers"].setdefault("go", [])
configs = {
    "5.7 intermediate": MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_INTERMEDIATE),
    "6.0 intermediate": TlsConfigurationAsJson.model_validate(config_60),
}
for name, config in configs.items():
    print(f"{name}: tls_curves={sorted(config.tls_curves)}")

requests = []
for target in targets:
    host, _, port = target.partition(":")
    location = ServerNetworkLocation(hostname=host, port=int(port or 443))
    requests.append(ServerScanRequest(server_location=location, scan_commands=SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER))
scanner = Scanner()
scanner.queue_scans(requests)
for result in scanner.get_results():
    target = result.server_location.display_string
    print(f"{target}: scan_status={result.scan_status.name}")
    for name, config in configs.items():
        try:
            check_server_against_tls_configuration(server_scan_result=result, tls_config_to_check_against=config)
            print(f"{target} [{name}]: compliant; tls_curves=<none>")
        except ServerNotCompliantWithTlsConfiguration as e:
            print(f"{target} [{name}]: not compliant; issues={sorted(e.issues)}; tls_curves={e.issues.get('tls_curves', '<none>')}")
        except ServerScanResultIncomplete as e:
            print(f"{target} [{name}]: incomplete scan: {e}")
EOF

echo "##### Versions"
run git rev-parse HEAD
run git fetch --no-tags --deepen=1 https://github.com/t0kubetsu/sslyze.git
run git log --format='%H %s' -2
run git ls-remote https://github.com/nabla-c0d3/sslyze.git refs/heads/dev refs/heads/release
run "$NASSL_OPENSSL" version
run python -c 'import importlib.metadata as m, nassl, sslyze; print("nassl", m.version("nassl"), nassl.__file__); print("sslyze", m.version("sslyze"), sslyze.__file__)'

echo "##### sslyze 6.3.1 from PyPI, in its own venv (run from $tmp so that the sslyze of this checkout is not imported)"
run python -m venv "$tmp/v631"
run "$tmp/v631/bin/python" -m pip install -q sslyze==6.3.1
(cd "$tmp" && run "$tmp/v631/bin/python" -c 'import importlib.metadata as m, nassl, sslyze; print("nassl", m.version("nassl"), nassl.__file__); print("sslyze", m.version("sslyze"), sslyze.__file__)')

echo "##### Profile facts"
run curl -sS -f -o "$tmp/tlsref-6.0.json" "$TLSREF_60"
run curl -sS -f -o "$tmp/tlsref-latest.json" "$TLSREF_LATEST"
run curl -sS -f -o "$tmp/mozilla-6.0.json" "$MOZILLA_60"
run cp sslyze/mozilla_tls_profile/5.7.json "$tmp/bundled-5.7.json"
(cd "$tmp" && run sha256sum tlsref-6.0.json tlsref-latest.json mozilla-6.0.json bundled-5.7.json)
cat > "$tmp/compare.py" <<'EOF'
import hashlib
import json
import sys

files = sys.argv[1:]
profiles = {f: json.load(open(f)) for f in files}
for f, p in profiles.items():
    configurations = json.dumps(p["configurations"], sort_keys=True).encode()
    print(f"{f}: version={p['version']} href={p['href']} configurations={list(p['configurations'])}"
          f" sha256(configurations, sort_keys)={hashlib.sha256(configurations).hexdigest()}")
    for name, c in p["configurations"].items():
        print(f"  {name}: tls_curves={c['tls_curves']} ciphers keys={sorted(c['ciphers'])}")
first = files[0]
for f in files[1:]:
    print(f"configurations identical: {first} == {f}: {profiles[first]['configurations'] == profiles[f]['configurations']}")
EOF
(cd "$tmp" && run python compare.py tlsref-6.0.json tlsref-latest.json mozilla-6.0.json bundled-5.7.json)
echo "### Control for the comparison: a changed copy must compare as different"
python -c 'import json,sys; p=json.load(open(sys.argv[1])); p["configurations"]["intermediate"]["tls_curves"].pop(0); json.dump(p, open(sys.argv[2], "w"))' "$tmp/tlsref-6.0.json" "$tmp/tlsref-6.0-changed.json"
(cd "$tmp" && run python compare.py tlsref-6.0.json tlsref-6.0-changed.json)
echo "### TLSRef 6.0 with the current models (expect validation errors for ciphers.caddy, ciphers.go and configurations.old)"
run python -c 'import json,sys,pydantic; from sslyze.mozilla_tls_profile.tls_config_checker import _MozillaTlsProfileAsJson as P
try:
    P(**json.load(open(sys.argv[1]))); print("loaded")
except pydantic.ValidationError as e:
    print(e.error_count(), "validation errors:", sorted(".".join(map(str, x["loc"])) for x in e.errors()))' "$tmp/tlsref-6.0.json"
echo "### Is X25519MLKEM768 a group name of the supported groups plugin?"
run python -c 'from sslyze.plugins.supported_groups_plugin import OpenSslGroupNameEnum as G; v={g.value for g in G}; print("X25519MLKEM768" in v, "x25519" in v)'
echo "### TLSRef documentation"
run curl -sS -f -o "$tmp/server-side-tls.html" https://docs.tlsref.org/server-side-tls.html
python - "$tmp/server-side-tls.html" <<'EOF'
import html, re, sys
text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", open(sys.argv[1], encoding="utf-8").read())))
for needle in ["maintains two recommended configurations", "The file will not change", "Remove Old configuration"]:
    m = re.search(re.escape(needle), text)
    print(f"{needle!r}: " + (text[max(0, m.start() - 150):m.end() + 150] if m else "NOT FOUND"))
EOF

echo "##### Local servers, 127.0.0.1"
start_server 44433 X25519MLKEM768:X25519
echo "### -groups X25519MLKEM768:X25519, sslyze of this checkout (expect tls_curves with only X25519MLKEM768)"
scan "fix branch" python 127.0.0.1:44433 "$REPO"
echo "### same server, sslyze 6.3.1 (comparison)"
scan "6.3.1" "$tmp/v631/bin/python" 127.0.0.1:44433 "$tmp"
echo "### same server, s_client offering only X25519MLKEM768 (expect Negotiated TLS1.3 group: X25519MLKEM768)"
pq_handshake 127.0.0.1 44433 localhost
echo "### same server, 5.7 and 6.0 intermediate (expect X25519MLKEM768 in tls_curves for 5.7 only)"
run python "$tmp/check_60.py" "$tmp/tlsref-6.0.json" 127.0.0.1:44433
stop_server
cat "$tmp/s_server.log"

start_server 44434 X25519
echo "### -groups X25519, sslyze of this checkout (expect tls_curves_lines=0)"
scan "fix branch" python 127.0.0.1:44434 "$REPO"
echo "### same server, sslyze 6.3.1 (comparison)"
scan "6.3.1" "$tmp/v631/bin/python" 127.0.0.1:44434 "$tmp"
echo "### same server, s_client offering only X25519MLKEM768 (control; expect a failed handshake)"
pq_handshake 127.0.0.1 44434 localhost
echo "### same server, 5.7 and 6.0 intermediate (expect no tls_curves for both)"
run python "$tmp/check_60.py" "$tmp/tlsref-6.0.json" 127.0.0.1:44434
stop_server
cat "$tmp/s_server.log"

echo "##### Live hosts"
for host in "${HOSTS[@]}"; do
  echo "### $host"
  scan "fix branch" python "$host" "$REPO"
  scan "6.3.1" "$tmp/v631/bin/python" "$host" "$tmp"
  pq_handshake "$host" 443 "$host"
done
echo "### Live hosts, 5.7 and 6.0 intermediate on the same scan results"
run python "$tmp/check_60.py" "$tmp/tlsref-6.0.json" "${HOSTS[@]}"

echo "##### Test of the old profile (www.mozilla.com)"
run python -m pytest "tests/test_mozilla_tls_profile/test_mozilla_tls_config.py::TestMozillaTlsConfigurationChecker::test_solo_cert_deployment_compliant_with_old" -p no:cacheprovider -rfE --tb=line

run git status --porcelain
exit 0
