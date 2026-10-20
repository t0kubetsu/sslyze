#!/usr/bin/env bash
# Verification of the fix for the connectivity check against servers that only accept post-quantum groups (#700).
# Every check prints its command, its output and "exit=<code>".
# sslyze exits 0 even when it discards a scan or a plugin crashes, so the verdict comes from the output text:
# the "discarded_scans=" / "error_blocks=" counts, the "groups:" lines, the "probing result:" lines, the ClientHello
# summaries and the pytest summary lines.
set -u

BASE_SHA=e175fff1e2d0f11a6696b7e2dc4203d4db92c902
# The checkouts must be on a file system that allows executing the test servers
WORK_DIR="${WORK_DIR:-/tmp}"
BASE_DIR="$WORK_DIR/base-700"
TESTS_ON_BASE_DIR="$WORK_DIR/tests-on-base-700"
TEST_FILES=(
  tests/plugins_tests/test_supported_groups_plugin.py
  tests/server_connectivity_tests/test_direct_connection.py
  tests/server_connectivity_tests/test_client_authentication.py
)
REGRESSION_TEST="tests/plugins_tests/test_supported_groups_plugin.py::TestSupportedGroupsPluginWithLocalServer::test_only_post_quantum_group_supported"
CHANGED_PY=(
  sslyze/server_connectivity.py
  tests/openssl_server/__init__.py
  tests/plugins_tests/test_supported_groups_plugin.py
)
PYTEST_ARGS=(-rfE -p no:cacheprovider -p no:logging)

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}

# Run sslyze, print its output, the number of "Error when running" blocks and of discarded scans, and the groups lines
scan() {
  echo "+ python -m sslyze $*"
  python -m sslyze "$@" > "$WORK_DIR/sslyze_out.txt" 2>&1
  local rc=$?
  cat "$WORK_DIR/sslyze_out.txt"
  echo "exit=$rc"
  echo "error_blocks=$(grep -c 'Error when running' "$WORK_DIR/sslyze_out.txt")"
  echo "discarded_scans=$(grep -c 'discarding scan' "$WORK_DIR/sslyze_out.txt")"
  grep -E 'groups:' "$WORK_DIR/sslyze_out.txt" | sed 's/^ */groups_line: /'
}

srv=
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null' EXIT

# $1: s_server binary, $2: port, then extra s_server arguments
start_server() {
  local openssl=$1 port=$2
  shift 2
  echo "+ $openssl s_server -cert $CERT -key $KEY -accept 127.0.0.1:$port -www $*"
  # stdout (ACCEPT line, -trace output) and stderr (errors) in separate files, so that they do not interleave
  "$openssl" s_server -cert "$CERT" -key "$KEY" -accept "127.0.0.1:$port" -www "$@" > "$WORK_DIR/s_server.log" 2> "$WORK_DIR/s_server.err" &
  srv=$!
  for _ in $(seq 50); do grep -q '^ACCEPT' "$WORK_DIR/s_server.log" && break; sleep 0.2; done
  grep -q '^ACCEPT' "$WORK_DIR/s_server.log" && echo "s_server ready" || { echo "s_server NOT ready"; cat "$WORK_DIR/s_server.log" "$WORK_DIR/s_server.err"; }
}

stop_server() {
  kill "$srv"
  wait "$srv" 2>/dev/null
  srv=
  echo "--- s_server stderr: lines with 'error' (with counts)"
  grep -i 'error' "$WORK_DIR/s_server.err" | sort | uniq -c
}

# Root cause: TLS 1.3 handshake of sslyze's SslConnection with each OpenSSL client, as in the connectivity check
root_cause() {
  echo "+ python - 127.0.0.1 $1 (SslConnection TLS 1.3, openssl_version=None / OPENSSL_1_1_1 / OPENSSL_4_0_0)"
  python - 127.0.0.1 "$1" <<'EOF'
import sys

from sslyze import ServerNetworkConfiguration, ServerNetworkLocation
from sslyze.connection_helpers.tls_connection import OpenSslVersionEnum, SslConnection
from sslyze.server_connectivity import TlsVersionEnum

location = ServerNetworkLocation(hostname="localhost", ip_address=sys.argv[1], port=int(sys.argv[2]))
config = ServerNetworkConfiguration.default_for_server_location(location)
for openssl_version in [None, OpenSslVersionEnum.OPENSSL_1_1_1, OpenSslVersionEnum.OPENSSL_4_0_0]:
    connection = SslConnection(
        server_location=location,
        network_configuration=config,
        tls_version=TlsVersionEnum.TLS_1_3,
        should_ignore_client_auth=False,
        openssl_version=openssl_version,
    )
    client_name = type(connection.ssl_client).__name__
    try:
        connection.connect(should_retry_connection=False)
        client = connection.ssl_client
        group = client.get_group_name().value if hasattr(client, "get_group_name") else "n/a"
        print(f"openssl_version={openssl_version} client={client_name} handshake=OK group={group}")
    except Exception as e:
        print(f"openssl_version={openssl_version} client={client_name} handshake=FAILED {type(e).__name__}: {e}")
    finally:
        connection.close()
EOF
  echo "exit=$?"
}

# Connectivity check only (check_connectivity_to_server()), as run by sslyze before any plugin
probe() {
  echo "+ python - 127.0.0.1 $1 (check_connectivity_to_server)"
  python - 127.0.0.1 "$1" <<'EOF'
import sys

import sslyze
from sslyze import ServerNetworkConfiguration, ServerNetworkLocation
from sslyze.server_connectivity import check_connectivity_to_server

print("sslyze module:", sslyze.__file__)
location = ServerNetworkLocation(hostname="localhost", ip_address=sys.argv[1], port=int(sys.argv[2]))
try:
    config = ServerNetworkConfiguration.default_for_server_location(location)
    print("probing result:", check_connectivity_to_server(location, config))
except Exception as e:
    print("probing error:", type(e).__name__, e)
EOF
  echo "exit=$?"
}

# Print each ClientHello received by s_server -trace, without the random values (random, session id, key shares)
client_hellos() {
  awk '/ClientHello, Length=/ {n++; inside=1; print "### ClientHello " n} inside && /^$/ {inside=0} inside' "$WORK_DIR/s_server.log" \
    | grep -v -E 'gmt_unix_time|random_bytes|session_id|key_exchange|^ +[0-9a-f]{4} - '
}

# $1: label (fix or base); run from the sslyze checkout to test
local_checks() {
  local label=$1
  run git rev-parse HEAD
  run python -c 'import sslyze; print(sslyze.__file__)'

  echo "### Root cause, PQ-only server: expect FAILED for None and OPENSSL_1_1_1, OK group=X25519MLKEM768 for OPENSSL_4_0_0"
  start_server "$NASSL_OPENSSL" 28480 -tls1_3 -groups X25519MLKEM768
  root_cause 28480
  stop_server

  echo "### AC: PQ-only server -tls1_3 -groups X25519MLKEM768"
  echo "### (fix: expect discarded_scans=0 and X25519MLKEM768 as the only supported group; base: expect discarded_scans=1)"
  start_server "$NASSL_OPENSSL" 28481 -tls1_3 -groups X25519MLKEM768
  echo "--- server check: s_client -groups X25519MLKEM768 (expect Negotiated TLS1.3 group: X25519MLKEM768)"
  run "$NASSL_OPENSSL" s_client -connect 127.0.0.1:28481 -tls1_3 -groups X25519MLKEM768 -brief < /dev/null
  scan --supported_groups 127.0.0.1:28481
  stop_server

  echo "### Informative: all the default scan commands against the same PQ-only server (error_blocks= counts the plugins that crashed)"
  start_server "$NASSL_OPENSSL" 28489 -tls1_3 -groups X25519MLKEM768
  scan 127.0.0.1:28489
  stop_server

  echo "### AC control: -tls1_3 -groups X25519 (expect X25519MLKEM768 in the rejected groups)"
  start_server "$NASSL_OPENSSL" 28482 -tls1_3 -groups X25519
  scan --supported_groups 127.0.0.1:28482
  stop_server

  echo "### AC control: -tls1_3 -groups X25519MLKEM768:X25519 (expect X25519MLKEM768 and X25519 supported)"
  start_server "$NASSL_OPENSSL" 28483 -tls1_3 -groups X25519MLKEM768:X25519
  scan --supported_groups 127.0.0.1:28483
  stop_server

  echo "### ClientHellos of the connectivity check, classic TLS 1.3 server (default groups); summaries saved for the diff"
  start_server "$NASSL_OPENSSL" 28484 -trace
  probe 28484
  stop_server
  client_hellos > "$WORK_DIR/client_hellos_tls13_$label.txt"
  echo "client_hellos=$(grep -c '^### ClientHello' "$WORK_DIR/client_hellos_tls13_$label.txt")"

  echo "### ClientHellos of the connectivity check, classic TLS 1.2-only server (-no_tls1_3); summaries saved for the diff"
  start_server "$NASSL_OPENSSL" 28485 -no_tls1_3 -trace
  probe 28485
  stop_server
  client_hellos > "$WORK_DIR/client_hellos_tls12_$label.txt"
  echo "client_hellos=$(grep -c '^### ClientHello' "$WORK_DIR/client_hellos_tls12_$label.txt")"

  echo "### Connectivity check, TLS 1.0-only server (-tls1 -cipher ALL:@SECLEVEL=0; expect the same result on base and fix)"
  start_server "$NASSL_OPENSSL" 28486 -tls1 -cipher 'ALL:@SECLEVEL=0'
  probe 28486
  stop_server

  echo "### Connectivity check, PQ-only server that requires a client certificate (-Verify 1)"
  start_server "$NASSL_OPENSSL" 28487 -tls1_3 -groups X25519MLKEM768 -Verify 1
  probe 28487
  stop_server

  echo "### Connectivity check, PQ-only server with optional client authentication (-verify 1)"
  start_server "$NASSL_OPENSSL" 28488 -tls1_3 -groups X25519MLKEM768 -verify 1
  probe 28488
  stop_server

  echo "### Live: www.cloudflare.com (expect X25519MLKEM768 supported)"
  scan --supported_groups www.cloudflare.com
}

echo "##### Versions"
run git rev-parse HEAD
run "$NASSL_OPENSSL" version
run python -c 'import importlib.metadata as m, nassl, sslyze; print("nassl", m.version("nassl"), nassl.__file__); print("sslyze", m.version("sslyze"), sslyze.__file__)'

# nassl is installed (not editable), so its source tree is no longer needed.
# Move it out of the sslyze checkout so that "ruff format .", "ruff check ." and "mypy ." only see sslyze.
if [ -d nassl-src ]; then
  run mv nassl-src "$WORK_DIR/nassl-src"
  NASSL_OPENSSL="$WORK_DIR/nassl-src${NASSL_OPENSSL#"$PWD/nassl-src"}"
  run "$NASSL_OPENSSL" version
fi

echo "##### Lint (invoke lint stops at the first failed command, so mypy and the changed files are also checked on their own)"
run python -m invoke lint
run mypy .
run ruff check "${CHANGED_PY[@]}"
run ruff format --check "${CHANGED_PY[@]}"
run git status --porcelain

echo "##### Exec bit of the OpenSSL 1.0.2 test server: known, out of scope; restored here for the tests only"
run git ls-files -s tests/openssl_server/openssl-1-0-2-linux64
run chmod +x tests/openssl_server/openssl-1-0-2-linux64

echo "##### The fix branch must not contain verification files (expect only the verification commit to add them)"
run git fetch --no-tags --deepen=10 origin
run git diff --stat HEAD~1 HEAD
run git ls-tree -r --name-only HEAD~1 -- verify .github/workflows/verify.yml
run git diff --stat "$BASE_SHA" HEAD~1

echo "##### Base checkouts: $BASE_DIR (base) and $TESTS_ON_BASE_DIR (tests of HEAD, sslyze/ of the base)"
run git worktree add --detach "$BASE_DIR" "$BASE_SHA"
run chmod +x "$BASE_DIR"/tests/openssl_server/openssl-1-0-2-linux64
run git worktree add --detach "$TESTS_ON_BASE_DIR" HEAD
run git -C "$TESTS_ON_BASE_DIR" checkout "$BASE_SHA" -- sslyze
run chmod +x "$TESTS_ON_BASE_DIR"/tests/openssl_server/openssl-1-0-2-linux64
run git -C "$TESTS_ON_BASE_DIR" diff --stat HEAD

echo "##### Lint control on the base: ruff check (expect the same EXE002 errors as on the fix branch)"
(cd "$BASE_DIR" && run ruff check .)

echo "##### Regression test, fix branch (expect 1 passed)"
run python -m pytest "$REGRESSION_TEST" "${PYTEST_ARGS[@]}" --tb=short
echo "##### Regression test, same test on the base code (expect 1 failed: the connectivity check does not detect TLS 1.3)"
(cd "$TESTS_ON_BASE_DIR" && run python -c 'import sslyze; print(sslyze.__file__)' && run python -m pytest "$REGRESSION_TEST" "${PYTEST_ARGS[@]}" --tb=short)

echo "##### Test files, fix branch"
run python -m pytest "${TEST_FILES[@]}" "${PYTEST_ARGS[@]}" --tb=line --show-capture=no
echo "##### Test files, base (control)"
(cd "$BASE_DIR" && run python -c 'import sslyze; print(sslyze.__file__)' && run python -m pytest "${TEST_FILES[@]}" "${PYTEST_ARGS[@]}" --tb=line --show-capture=no)

export CERT="$PWD/tests/server_certificates/rsa/server-rsa-cert.pem"
export KEY="$PWD/tests/server_certificates/rsa/server-rsa-key.pem"
echo "##### Local and live checks, fix branch"
local_checks fix
echo "##### Local and live checks, base (control)"
(cd "$BASE_DIR" && local_checks base)

echo "##### ClientHellos of the connectivity check: base vs. fix"
echo "### Classic TLS 1.3 server (expect no difference)"
run diff "$WORK_DIR/client_hellos_tls13_base.txt" "$WORK_DIR/client_hellos_tls13_fix.txt"
echo "### TLS 1.2-only server (expect one more ClientHello on the fix: the TLS 1.3 retry with the OpenSSL 4.0.0 client)"
run diff "$WORK_DIR/client_hellos_tls12_base.txt" "$WORK_DIR/client_hellos_tls12_fix.txt"
echo "### ClientHello summaries, fix branch"
run cat "$WORK_DIR/client_hellos_tls13_fix.txt" "$WORK_DIR/client_hellos_tls12_fix.txt"

exit 0
