#!/usr/bin/env bash
# Checks for the --ech retry config fix: lint, the ECH plugin tests, local ECH servers and live hosts.
# Every check prints its command and its exit code; one failed check does not stop the next ones.
set -u

run() {
    echo "+ $*"
    "$@"
    echo "exit=$?"
}

srv=
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null' EXIT

: "${NASSL_OPENSSL:?NASSL_OPENSSL must point to the OpenSSL 4 openssl binary of the nassl build}"
CERT=tests/server_certificates/rsa/server-rsa-cert.pem
KEY=tests/server_certificates/rsa/server-rsa-key.pem
ECH_KEY=tests/server_certificates/ech-config.pem
PORT=44433

# Start s_server on 127.0.0.1:$PORT with the extra arguments given, and wait for its ACCEPT line
start_server() {
    "$NASSL_OPENSSL" s_server -tls1_3 -cert "$CERT" -key "$KEY" -accept "127.0.0.1:$PORT" -www "$@" > /tmp/s_server.log 2>&1 &
    srv=$!
    for _ in $(seq 50); do grep -q '^ACCEPT' /tmp/s_server.log && break; sleep 0.2; done
    echo "s_server pid=$srv args: $*"
}

stop_server() {
    kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null; srv=
    echo "--- s_server log"
    cat /tmp/s_server.log
    echo "---"
}

# Runs the sslyze CLI with the ECHConfigList from the ECHCONFIG PEM section of $1 used as if it was published in the
# server's DNS record (a local server has no HTTPS record), and counts the ECH handshakes the plugin makes
cat > /tmp/ech_cli.py <<'EOF'
import sys
from base64 import b64decode
from unittest import mock

import sslyze.plugins.encrypted_client_hello_plugin as ech
from sslyze.__main__ import main

pem_text = open(sys.argv[1]).read()
ech_config_list = b64decode(pem_text.split("-----BEGIN ECHCONFIG-----")[1].split("-----END ECHCONFIG-----")[0])
print(f"ECHConfigList used as the DNS record: {len(ech_config_list)} bytes")
original_do_ech_handshake = ech._do_ech_handshake
handshakes = []


def counting_do_ech_handshake(server_info, config_list):
    handshakes.append(config_list == ech_config_list)
    return original_do_ech_handshake(server_info, config_list)


with (
    mock.patch.object(ech, "_fetch_ech_config_list_from_dns", return_value=ech_config_list),
    mock.patch.object(ech, "_do_ech_handshake", side_effect=counting_do_ech_handshake),
):
    sys.argv = ["sslyze", *sys.argv[2:]]
    main()
print(f"ECH handshakes made by the plugin: {len(handshakes)}; with the DNS ECHConfigList: {handshakes}")
EOF

echo "=== versions"
run git rev-parse HEAD
run python -c 'import sslyze, nassl; print("sslyze", sslyze.__version__, sslyze.__file__); print("nassl", nassl.__version__)'
run "$NASSL_OPENSSL" version

echo "=== lint"
# The workflow checks nassl out into ./nassl-src; move it out of the tree while linting, so that ruff and mypy only
# check sslyze (nassl is already installed; NASSL_OPENSSL points into nassl-src, which is moved back afterwards)
moved_nassl_src=
if [ -d nassl-src ]; then run mv nassl-src ../nassl-src && moved_nassl_src=1; fi
run python -m invoke lint
# invoke stops at the first failing step; run the remaining steps on their own so that each result is visible
run ruff check . --ignore EXE002
run mypy .
run git status --porcelain
if [ -n "$moved_nassl_src" ]; then run mv ../nassl-src nassl-src; fi

echo "=== ECH plugin tests"
# The ECH fixture path of the local test server is wrong on dev (fixed separately); correct it here, not committed
run sed -i 's|ECH_CONFIG_PATH = Path(__file__).parent.absolute() / "ech-config.pem"|ECH_CONFIG_PATH = _CERTS_FOLDER / "ech-config.pem"|' tests/openssl_server/__init__.py
run git diff tests/openssl_server/__init__.py
run python -m pytest tests/plugins_tests/test_encrypted_client_hello_plugin.py -v -p no:cacheprovider
run git checkout -- tests/openssl_server/__init__.py

echo "=== Local ECH servers"
# An ECHConfigList with a new key, that the server does not have: what a DNS record holds after a key rotation
run "$NASSL_OPENSSL" ech -public_name localhost -out /tmp/stale-ech.pem
run sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/p' /tmp/stale-ech.pem
run sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/p' "$ECH_KEY"

echo "--- Check 1: server with -ech_key $ECH_KEY, DNS record = stale ECHConfigList"
echo "    Expected: 'OK - Server supports ECH, but the ECHConfigList published via DNS is outdated', 2 handshakes"
start_server -ech_key "$ECH_KEY"
run python /tmp/ech_cli.py /tmp/stale-ech.pem --ech --json_out /tmp/check1.json "localhost:$PORT{127.0.0.1}"
run python -c 'import json; r = json.load(open("/tmp/check1.json"))["server_scan_results"][0]["scan_result"]["encrypted_client_hello"]; print(r["status"], {k: v for k, v in (r["result"] or {}).items() if k != "ech_config_list_from_dns"})'
stop_server

echo "--- Control 2: server with -ech_key $ECH_KEY, DNS record = the server's own ECHConfigList"
echo "    Expected: 'OK - Server supports ECH and publishes a valid ECHConfigList', 1 handshake"
start_server -ech_key "$ECH_KEY"
run python /tmp/ech_cli.py "$ECH_KEY" --ech "localhost:$PORT{127.0.0.1}"
stop_server

echo "--- Control 3: server without -ech_key, DNS record = the ECHConfigList of $ECH_KEY"
echo "    Expected: 'NOT SUPPORTED - ... did NOT lead to a working ECH handshake', 1 handshake (no retry)"
start_server
run python /tmp/ech_cli.py "$ECH_KEY" --ech "localhost:$PORT{127.0.0.1}"
stop_server

echo "--- Control 4: server without -ech_key, DNS record = stale ECHConfigList"
echo "    Expected: 'NOT SUPPORTED - ... did NOT lead to a working ECH handshake', 1 handshake (no retry)"
start_server
run python /tmp/ech_cli.py /tmp/stale-ech.pem --ech "localhost:$PORT{127.0.0.1}"
stop_server

echo "=== Live hosts"
echo "    Expected (same as dev): defo.ie OK, crypto.cloudflare.com OK, example.com NOT SUPPORTED"
run python -m sslyze --ech defo.ie crypto.cloudflare.com example.com

exit 0
