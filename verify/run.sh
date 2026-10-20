#!/usr/bin/env bash
# Verification of the fixes for the --tlsv1_1, --heartbleed and --supported_groups crashes (#732).
# Every check prints its command, its output and "exit=<code>".
# sslyze exits 0 even when a plugin crashes, so the verdict comes from the output text:
# the "error_blocks=" count of "Error when running" blocks, and the pytest summary lines.
set -u

BASE_SHA=e175fff1e2d0f11a6696b7e2dc4203d4db92c902
# The checkouts must be on a file system that allows executing the test servers
WORK_DIR="${WORK_DIR:-/tmp}"
BASE_DIR="$WORK_DIR/base-732"
TESTS_ON_BASE_DIR="$WORK_DIR/tests-on-base-732"
LIVE_HOST="新华网.中国"
TEST_FILES=(
  tests/plugins_tests/test_heartbleed_plugin.py
  tests/plugins_tests/openssl_cipher_suites/
  tests/plugins_tests/test_supported_groups_plugin.py
)
# One or more tests per crash: heartbleed (2), --tlsv1_1 (1), --supported_groups NULL group (3), DH key too small (4)
REGRESSION_TESTS=(
  tests/plugins_tests/test_heartbleed_plugin.py::TestHeartbleedPlugin::test_vulnerable
  tests/plugins_tests/test_heartbleed_plugin.py::TestHeartbleedPlugin::test_vulnerable_and_server_has_sni_bug
  tests/plugins_tests/test_heartbleed_plugin.py::TestHeartbleedPlugin::test_succeeds_when_client_auth_failed
  tests/plugins_tests/openssl_cipher_suites/test_openssl_cipher_suites_plugin.py::TestCipherSuitesPluginWithLocalServer::test_tlsv1_1_disabled
  tests/plugins_tests/test_supported_groups_plugin.py::TestSupportedGroupsPluginWithLocalServer::test_no_ecdh_cipher_suites_supported
  tests/plugins_tests/test_supported_groups_plugin.py::TestSupportedGroupsPluginWithLocalServer::test_tls_1_3_not_supported
)
CHANGED_PY=(
  sslyze/connection_helpers/tls_connection.py
  sslyze/plugins/heartbleed_plugin.py
  sslyze/plugins/supported_groups_plugin.py
  tests/openssl_server/__init__.py
  tests/plugins_tests/openssl_cipher_suites/test_openssl_cipher_suites_plugin.py
)
PYTEST_ARGS=(-rfE -p no:cacheprovider -p no:logging)

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}

# Run sslyze, print its output and the number of "Error when running" blocks
scan() {
  echo "+ python -m sslyze $*"
  python -m sslyze "$@" > /tmp/sslyze_out.txt 2>&1
  local rc=$?
  cat /tmp/sslyze_out.txt
  echo "exit=$rc"
  echo "error_blocks=$(grep -c 'Error when running' /tmp/sslyze_out.txt)"
  echo "discarded_scans=$(grep -c 'discarding scan' /tmp/sslyze_out.txt)"
}

srv=
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null' EXIT

start_server() {
  local port=$1
  shift
  echo "+ $NASSL_OPENSSL s_server -cert $CERT -key $KEY -accept 127.0.0.1:$port -www $*"
  "$NASSL_OPENSSL" s_server -cert "$CERT" -key "$KEY" -accept "127.0.0.1:$port" -www "$@" > /tmp/s_server.log 2>&1 &
  srv=$!
  for _ in $(seq 50); do grep -q '^ACCEPT' /tmp/s_server.log && break; sleep 0.2; done
  grep -q '^ACCEPT' /tmp/s_server.log && echo "s_server ready" || { echo "s_server NOT ready"; cat /tmp/s_server.log; }
}

stop_server() {
  kill "$srv"
  wait "$srv" 2>/dev/null
  srv=
  echo "--- s_server log (first 3 lines)"
  head -3 /tmp/s_server.log
}

# Local reproductions with OpenSSL 4 s_server bound to 127.0.0.1, run from the current directory
# (ports below the ephemeral port range, so that they are free on the runner)
local_checks() {
  run git rev-parse HEAD
  run python -c 'import sslyze; print(sslyze.__file__)'

  echo "### Crash 1: --tlsv1_1, server supports TLS 1.2 and TLS 1.0 but not TLS 1.1 (expect 0 accepted cipher suites)"
  start_server 28461 -no_tls1_1 -no_tls1_3 -cipher 'ALL:@SECLEVEL=0'
  scan --tlsv1_1 127.0.0.1:28461
  stop_server
  echo "### Crash 1 control: same server with TLS 1.1 enabled (expect accepted TLS 1.1 cipher suites)"
  start_server 28462 -no_tls1_3 -cipher 'ALL:@SECLEVEL=0'
  scan --tlsv1_1 127.0.0.1:28462
  stop_server

  echo "### Crash 2: --heartbleed, server supports up to TLS 1.2 (expect OK - Not vulnerable to Heartbleed)"
  start_server 28463 -no_tls1_3
  scan --heartbleed 127.0.0.1:28463
  stop_server

  echo "### Crash 3: --supported_groups, TLS 1.2 server with RSA key exchange only (expect all FFDH groups rejected)"
  start_server 28464 -no_tls1_3 -cipher AES128-SHA
  scan --supported_groups 127.0.0.1:28464
  stop_server
  echo "### Crash 3: --supported_groups, TLS 1.2 server with DHE and a 1024-bit group that is not an FFDH group"
  run "$NASSL_OPENSSL" genpkey -genparam -algorithm DH -pkeyopt group:dh_1024_160 -out /tmp/dh1024.pem
  start_server 28465 -no_tls1_3 -cipher 'DHE-RSA-AES128-SHA:@SECLEVEL=0' -dhparam /tmp/dh1024.pem
  scan --supported_groups 127.0.0.1:28465
  stop_server
  echo "### Crash 3, limit of the fix: TLS 1.2 server with DHE and ffdhe2048 (OpenSSL returns no group name)"
  start_server 28466 -no_tls1_3 -cipher DHE-RSA-AES128-GCM-SHA256 -groups ffdhe2048
  scan --supported_groups 127.0.0.1:28466
  stop_server
  echo "### Crash 3 control: TLS 1.2 server with RSA key exchange and ECDHE with x25519 (expect x25519 supported)"
  start_server 28467 -no_tls1_3 -cipher 'AES128-SHA:ECDHE-RSA-AES128-SHA' -groups x25519
  scan --supported_groups 127.0.0.1:28467
  stop_server

  echo "### Side effect of the --tlsv1_1 fix: TLS 1.0-only server, --tlsv1 (fix: expect discarded_scans=0 and accepted TLS 1.0 cipher suites; base: discarded_scans=1)"
  start_server 28468 -tls1 -cipher 'ALL:@SECLEVEL=0'
  scan --tlsv1 127.0.0.1:28468
  stop_server
  echo "### Side effect control: same TLS 1.0 cipher suites, server also supports TLS 1.2 (expect discarded_scans=0 on fix and base)"
  start_server 28469 -no_tls1_1 -no_tls1_3 -cipher 'ALL:@SECLEVEL=0'
  scan --tlsv1 127.0.0.1:28469
  stop_server
}

echo "##### Versions"
run git rev-parse HEAD
run "$NASSL_OPENSSL" version
run python -c 'import importlib.metadata as m, nassl, sslyze; print("nassl", m.version("nassl"), nassl.__file__); print("sslyze", m.version("sslyze"), sslyze.__file__)'

# nassl is installed (not editable), so its source tree is no longer needed.
# Move it out of the sslyze checkout so that "ruff format .", "ruff check ." and "mypy ." only see sslyze.
if [ -d nassl-src ]; then
  run mv nassl-src /tmp/nassl-src
  NASSL_OPENSSL="/tmp/nassl-src${NASSL_OPENSSL#"$PWD/nassl-src"}"
  run "$NASSL_OPENSSL" version
fi

echo "##### Lint (invoke lint stops at the first failed command, so mypy and the changed files are also checked on their own)"
run python -m invoke lint
run mypy .
run ruff check "${CHANGED_PY[@]}"
run ruff format --check "${CHANGED_PY[@]}"
run git status --porcelain

echo "##### Exec bit of the OpenSSL 1.0.2 test server: fixed in another change, restored here for the tests only"
run git ls-files -s tests/openssl_server/openssl-1-0-2-linux64
run chmod +x tests/openssl_server/openssl-1-0-2-linux64

echo "##### Base checkouts: $BASE_DIR (base) and $TESTS_ON_BASE_DIR (tests of HEAD, sslyze/ of the base)"
run git fetch --no-tags --deepen=10 origin

echo "##### The fix branch must not contain verification files (expect only the verification commit to add them)"
run git diff --stat HEAD~1 HEAD
run git ls-tree -r --name-only HEAD~1 -- verify .github/workflows/verify.yml
run git worktree add --detach "$BASE_DIR" "$BASE_SHA"
run chmod +x "$BASE_DIR"/tests/openssl_server/openssl-1-0-2-linux64
run git worktree add --detach "$TESTS_ON_BASE_DIR" HEAD
run git -C "$TESTS_ON_BASE_DIR" checkout "$BASE_SHA" -- sslyze
run chmod +x "$TESTS_ON_BASE_DIR"/tests/openssl_server/openssl-1-0-2-linux64
run git -C "$TESTS_ON_BASE_DIR" diff --stat HEAD

echo "##### Lint control on the base: ruff check (expect the same EXE002 errors as on the fix branch)"
(cd "$BASE_DIR" && run ruff check .)

echo "##### Regression tests, fix branch (expect 6 passed)"
run python -m pytest "${REGRESSION_TESTS[@]}" "${PYTEST_ARGS[@]}" --tb=short
echo "##### Regression tests, same tests on the base code (expect 6 failed)"
(cd "$TESTS_ON_BASE_DIR" && run python -c 'import sslyze; print(sslyze.__file__)' && run python -m pytest "${REGRESSION_TESTS[@]}" "${PYTEST_ARGS[@]}" --tb=line)

echo "##### Test files, fix branch"
run python -m pytest "${TEST_FILES[@]}" -k "not OnlineServer" "${PYTEST_ARGS[@]}" --tb=short
echo "##### Test files, base (control)"
(cd "$BASE_DIR" && run python -m pytest "${TEST_FILES[@]}" -k "not OnlineServer" "${PYTEST_ARGS[@]}" --tb=line)

echo "##### Local reproductions, fix branch (expect error_blocks=0 and discarded_scans=0 everywhere)"
export CERT="$PWD/tests/server_certificates/rsa/server-rsa-cert.pem"
export KEY="$PWD/tests/server_certificates/rsa/server-rsa-key.pem"
local_checks
echo "##### Local reproductions, base (control; expect error_blocks=1 for crashes 1, 2 and 3)"
(cd "$BASE_DIR" && local_checks)

echo "##### Live host, fix branch (expect error_blocks=0)"
scan --tlsv1_1 --heartbleed --supported_groups --slow_connection "$LIVE_HOST"
echo "##### Live host, base (control)"
(cd "$BASE_DIR" && scan --tlsv1_1 --heartbleed --supported_groups --slow_connection "$LIVE_HOST")

exit 0
