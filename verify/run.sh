#!/usr/bin/env bash
# Verification of the fix for the --supported_groups crash with the brainpoolP*r1tls13 groups (#722).
# Every check prints its command, its output and "exit=<code>".
# sslyze exits 0 even when a plugin crashes or a scan is discarded, so the verdict comes from the output text:
# the "error_blocks=" / "discarded_scans=" counts, the "Supported/Rejected Elliptic Curve groups" lines and the
# pytest summary lines.
set -u

BASE_SHA=e175fff1e2d0f11a6696b7e2dc4203d4db92c902
# The checkouts must be on a file system that allows executing the test servers
WORK_DIR="${WORK_DIR:-/tmp}"
BASE_DIR="$WORK_DIR/base-722"
TESTS_ON_BASE_DIR="$WORK_DIR/tests-on-base-722"
TEST_FILE=tests/plugins_tests/test_supported_groups_plugin.py
REGRESSION_TEST="$TEST_FILE::TestSupportedGroupsPluginWithLocalServer::test_brainpool_tls_1_3_groups_supported"
CHANGED_PY=(
  sslyze/plugins/supported_groups_plugin.py
  tests/openssl_server/__init__.py
  tests/plugins_tests/test_supported_groups_plugin.py
)
PYTEST_ARGS=(-rfE -p no:cacheprovider -p no:logging)

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}

# Run sslyze, print its output, the number of "Error when running" blocks and of discarded scans
scan() {
  echo "+ python -m sslyze $*"
  python -m sslyze "$@" > "$WORK_DIR/sslyze_out.txt" 2>&1
  local rc=$?
  cat "$WORK_DIR/sslyze_out.txt"
  echo "exit=$rc"
  echo "error_blocks=$(grep -c 'Error when running' "$WORK_DIR/sslyze_out.txt")"
  echo "assertion_errors=$(grep -c 'AssertionError' "$WORK_DIR/sslyze_out.txt")"
  echo "discarded_scans=$(grep -c 'discarding scan' "$WORK_DIR/sslyze_out.txt")"
  grep -E 'Elliptic Curve groups:' "$WORK_DIR/sslyze_out.txt" | sed 's/^ */groups_line: /'
}

srv=
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null' EXIT

start_server() {
  local port=$1
  shift
  echo "+ $NASSL_OPENSSL s_server -cert $CERT -key $KEY -accept 127.0.0.1:$port -www $*"
  "$NASSL_OPENSSL" s_server -cert "$CERT" -key "$KEY" -accept "127.0.0.1:$port" -www "$@" > "$WORK_DIR/s_server.log" 2>&1 &
  srv=$!
  for _ in $(seq 50); do grep -q '^ACCEPT' "$WORK_DIR/s_server.log" && break; sleep 0.2; done
  grep -q '^ACCEPT' "$WORK_DIR/s_server.log" && echo "s_server ready" || { echo "s_server NOT ready"; cat "$WORK_DIR/s_server.log"; }
}

stop_server() {
  kill "$srv"
  wait "$srv" 2>/dev/null
  srv=
  echo "--- s_server log (first 3 lines)"
  head -3 "$WORK_DIR/s_server.log"
}

# Root cause: for the brainpoolP*r1tls13 groups, nassl's get_group_name() returns the TLS 1.3 group, but the
# ephemeral key's curve_name returns the brainpool curve (same OpenSSL NID as the TLS 1.2 group)
root_cause() {
  echo "+ python - 127.0.0.1 $1 (nassl client: get_group_name() vs. get_ephemeral_key().curve_name)"
  python - 127.0.0.1 "$1" <<'EOF'
import socket
import sys

from nassl.base_ssl_client import OpenSslVerifyEnum
from nassl.ephemeral_key_info import OpenSslGroupNameEnum
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0
from nassl.tls_version_enum import TlsVersionEnum

host, port = sys.argv[1], int(sys.argv[2])
for tls_version, group in [
    (TlsVersionEnum.TLS_1_3, OpenSslGroupNameEnum.brainpoolP256r1tls13),
    (TlsVersionEnum.TLS_1_3, OpenSslGroupNameEnum.brainpoolP384r1tls13),
    (TlsVersionEnum.TLS_1_3, OpenSslGroupNameEnum.brainpoolP512r1tls13),
    (TlsVersionEnum.TLS_1_2, OpenSslGroupNameEnum.brainpoolP256r1),
]:
    sock = socket.create_connection((host, port), timeout=5)
    client = SslClient_OpenSSL_4_0_0(underlying_socket=sock, tls_version=tls_version, ssl_verify=OpenSslVerifyEnum.NONE)
    client.set_groups_list([group])
    client.do_handshake()
    key = client.get_ephemeral_key()
    group_name = client.get_group_name()
    print(
        f"{tls_version.name} requested={group.value} get_group_name()={group_name.value}"
        f" key.curve={key.curve} key.curve_name={key.curve_name.value} equal={key.curve_name == group_name}"
    )
    client.shutdown()
    sock.close()
EOF
  echo "exit=$?"
}

# Local checks with OpenSSL 4 s_server bound to 127.0.0.1, run from the current directory
# (ports below the ephemeral port range, so that they are free on the runner)
local_checks() {
  run git rev-parse HEAD
  run python -c 'import sslyze; print(sslyze.__file__)'

  echo "### Root cause (expect equal=False for the 3 tls13 groups, equal=True for TLS 1.2 brainpoolP256r1)"
  start_server 28470 -groups brainpoolP256r1tls13:brainpoolP384r1tls13:brainpoolP512r1tls13:brainpoolP256r1
  root_cause 28470
  stop_server

  echo "### Check 1, issue command: TLS 1.3 server with only the brainpoolP*r1tls13 groups"
  echo "### (sslyze's connectivity check offers none of these groups, so expect discarded_scans=1 on base and fix)"
  start_server 28471 -tls1_3 -groups brainpoolP256r1tls13:brainpoolP384r1tls13:brainpoolP512r1tls13
  scan --supported_groups 127.0.0.1:28471
  stop_server

  echo "### Check 1: same server plus x25519 for the connectivity check"
  echo "### (base: expect error_blocks=1 and assertion_errors=1; fix: expect the 3 tls13 groups in Supported)"
  start_server 28472 -tls1_3 -groups x25519:brainpoolP256r1tls13:brainpoolP384r1tls13:brainpoolP512r1tls13
  scan --supported_groups 127.0.0.1:28472
  stop_server

  echo "### Check 1 control: same server with -groups x25519 (expect the 3 tls13 groups in Rejected, error_blocks=0)"
  start_server 28473 -tls1_3 -groups x25519
  scan --supported_groups 127.0.0.1:28473
  stop_server

  echo "### Check 2, issue control: TLS 1.2 server with -groups brainpoolP256r1"
  echo "### (DHE is enabled: the FFDH probes hit the known NULL group name crash, out of scope, on base and fix)"
  start_server 28474 -tls1_2 -groups brainpoolP256r1
  scan --supported_groups 127.0.0.1:28474
  stop_server

  echo "### Check 2b: TLS 1.2 server with -groups x25519:brainpoolP256r1 and one ECDHE cipher suite only"
  echo "### (expect brainpoolP256r1 and x25519 in Supported, the same on base and fix)"
  start_server 28475 -tls1_2 -groups x25519:brainpoolP256r1 -cipher ECDHE-RSA-AES128-GCM-SHA256
  scan --supported_groups 127.0.0.1:28475
  stop_server
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
echo "##### Regression test, same test on the base code (expect 1 failed, AssertionError: Should never happen)"
(cd "$TESTS_ON_BASE_DIR" && run python -c 'import sslyze; print(sslyze.__file__)' && run python -m pytest "$REGRESSION_TEST" "${PYTEST_ARGS[@]}" --tb=short)

echo "##### Test file, fix branch"
run python -m pytest "$TEST_FILE" "${PYTEST_ARGS[@]}" --tb=short
echo "##### Test file, base (control)"
(cd "$BASE_DIR" && run python -m pytest "$TEST_FILE" "${PYTEST_ARGS[@]}" --tb=line)

echo "##### Local checks, fix branch"
export CERT="$PWD/tests/server_certificates/rsa/server-rsa-cert.pem"
export KEY="$PWD/tests/server_certificates/rsa/server-rsa-key.pem"
local_checks
echo "##### Local checks, base (control)"
(cd "$BASE_DIR" && local_checks)

exit 0
