#!/usr/bin/env bash
# Verification of the X25519/X448 name mapping of the Mozilla TLS config checker.
# Every check prints its command, its output and "exit=<code>".
# sslyze exits 1 when the server is not compliant, so the verdict comes from the "tls_curves" line
# (and the "tls_curves_lines=" count), and from the pytest summary lines.
set -u

BASE_SHA=e175fff1e2d0f11a6696b7e2dc4203d4db92c902
WORK_DIR="${WORK_DIR:-/tmp}"
BASE_DIR="$WORK_DIR/base-mozilla"
TESTS_ON_BASE_DIR="$WORK_DIR/tests-on-base-mozilla"
CHANGED_PY=(
  sslyze/mozilla_tls_profile/tls_config_checker.py
  tests/test_mozilla_tls_profile/test_mozilla_tls_config.py
)
PYTEST_ARGS=(-v -rfE -p no:cacheprovider)

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}

# Run sslyze --mozilla_config=intermediate and print the lines that decide the check
scan() {
  echo "+ python -m sslyze --mozilla_config=intermediate $1"
  python -m sslyze --mozilla_config=intermediate "$1" > /tmp/sslyze_out.txt 2>&1
  echo "exit=$?"
  grep -E "Supported (Elliptic Curve|Post-Quantum) groups|COMPLIANCE|compliant|tls_curves|discarding scan|TLS probing failed|Error when running" /tmp/sslyze_out.txt
  echo "tls_curves_lines=$(grep -c 'tls_curves' /tmp/sslyze_out.txt)"
}

srv=
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null' EXIT

start_server() {
  local port=$1 groups=$2
  echo "+ $NASSL_OPENSSL s_server -cert $CERT -key $KEY -accept 127.0.0.1:$port -www -groups $groups"
  "$NASSL_OPENSSL" s_server -cert "$CERT" -key "$KEY" -accept "127.0.0.1:$port" -www -groups "$groups" > /tmp/s_server.log 2>&1 &
  srv=$!
  for _ in $(seq 50); do grep -q '^ACCEPT' /tmp/s_server.log && break; sleep 0.2; done
  grep -q '^ACCEPT' /tmp/s_server.log && echo "s_server ready" || { echo "s_server NOT ready"; cat /tmp/s_server.log; }
}

stop_server() {
  kill "$srv"
  wait "$srv" 2>/dev/null
  srv=
}

# Local servers bound to 127.0.0.1, scanned with the code of the current directory
local_checks() {
  run git rev-parse HEAD
  run python -c 'import sslyze; print(sslyze.__file__)'
  echo "### -groups X25519:secp521r1 (fix: only secp521r1 flagged; base: x25519 and secp521r1 flagged)"
  start_server 28471 X25519:secp521r1
  scan 127.0.0.1:28471
  stop_server
  echo "### -groups X448 (control, fix and base: x448 flagged)"
  start_server 28472 X448
  scan 127.0.0.1:28472
  stop_server
  echo "### -groups X25519 (fix: tls_curves_lines=0; base: x25519 flagged)"
  start_server 28473 X25519
  scan 127.0.0.1:28473
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

echo "##### The fix branch must not contain verification files (expect only the verification commit to add them)"
run git fetch --no-tags --deepen=10 origin
run git diff --stat HEAD~1 HEAD
run git ls-tree -r --name-only HEAD~1 -- verify .github/workflows/verify.yml

echo "##### Base checkouts: $BASE_DIR (base) and $TESTS_ON_BASE_DIR (tests of HEAD, sslyze/ of the base)"
run git worktree add --detach "$BASE_DIR" "$BASE_SHA"
run git worktree add --detach "$TESTS_ON_BASE_DIR" HEAD
run git -C "$TESTS_ON_BASE_DIR" checkout "$BASE_SHA" -- sslyze
run git -C "$TESTS_ON_BASE_DIR" diff --stat HEAD

echo "##### Lint control on the base: ruff check (expect the same EXE002 errors as on the fix branch)"
(cd "$BASE_DIR" && run ruff check .)

echo "##### Mozilla tests, fix branch (expect all passed, none failed)"
run python -m pytest tests/test_mozilla_tls_profile "${PYTEST_ARGS[@]}"
echo "##### Mozilla tests of the fix branch on the base code (expect test_solo_cert_deployment_compliant_with_old and the 3 new tests failed)"
(cd "$TESTS_ON_BASE_DIR" && run python -c 'import sslyze; print(sslyze.__file__)' && run python -m pytest tests/test_mozilla_tls_profile "${PYTEST_ARGS[@]}" --tb=line)
echo "##### Mozilla tests of the base on the base code (expect test_solo_cert_deployment_compliant_with_old failed)"
(cd "$BASE_DIR" && run python -c 'import sslyze; print(sslyze.__file__)' && run python -m pytest tests/test_mozilla_tls_profile "${PYTEST_ARGS[@]}" --tb=line)

echo "##### Local servers, fix branch"
export CERT="$PWD/tests/server_certificates/rsa/server-rsa-cert.pem"
export KEY="$PWD/tests/server_certificates/rsa/server-rsa-key.pem"
local_checks
echo "##### Local servers, base (control)"
(cd "$BASE_DIR" && local_checks)

echo "##### Live host, fix branch (expect tls_curves with exactly secp521r1 and X25519MLKEM768)"
scan www.cloudflare.com
echo "##### Live host, base (control; expect x25519 in tls_curves too)"
(cd "$BASE_DIR" && scan www.cloudflare.com)

echo "##### Full suite, fix branch"
run python -m invoke test
run git status --porcelain
echo "##### Full suite, base (control for the classification of failures)"
(cd "$BASE_DIR" && run python -m invoke test)

exit 0
