#!/usr/bin/env bash
# Verification of the test setup fixes (exec bit, group name case, ECH config path).
# Every check prints its command, its output and "exit=<code>".
# The verdict comes from the pytest summary lines and the failure messages, not from the exit code alone.
set -u

BASE_SHA=e175fff1e2d0f11a6696b7e2dc4203d4db92c902
AC1_TESTS=(tests/plugins_tests/test_supported_groups_plugin.py tests/plugins_tests/test_encrypted_client_hello_plugin.py)
CHANGED_PY=(tests/openssl_server/__init__.py tests/plugins_tests/test_supported_groups_plugin.py)

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}

echo "##### Versions"
run git rev-parse HEAD
run "$NASSL_OPENSSL" version
run python -c 'import importlib.metadata as m, nassl, sslyze; print("nassl", m.version("nassl"), nassl.__file__); print("sslyze", m.version("sslyze"), sslyze.__file__)'

# nassl is installed (not editable), so its source tree is no longer needed.
# Move it out of the sslyze checkout so that "ruff format .", "ruff check ." and "mypy ." only see sslyze.
if [ -d nassl-src ]; then run mv nassl-src /tmp/nassl-src; fi

echo "##### AC3: modes of the test server binaries (expect 100755 for the three openssl-*-linux64)"
run git ls-files -s tests/openssl_server/
run ls -l tests/openssl_server/

echo "##### Lint on the fix branch"
run python -m invoke lint
echo "--- invoke lint stops at the first failed command, so run mypy and the checks of the changed files on their own"
run mypy .
run ruff check "${CHANGED_PY[@]}"
run ruff format --check "${CHANGED_PY[@]}"
run git status --porcelain

echo "##### AC1 after (fix branch)"
run python -m pytest "${AC1_TESTS[@]}" -k "not OnlineServer" -v -rfE -p no:cacheprovider

echo "##### Base checkout for the controls ($BASE_SHA)"
run git fetch --no-tags --deepen=10 origin
run git worktree add --detach /tmp/base "$BASE_SHA"
run git -C /tmp/base rev-parse HEAD
run git -C /tmp/base ls-files -s tests/openssl_server/

echo "##### Lint control on the base: ruff check (expect the same result as on the fix branch)"
(cd /tmp/base && run ruff check .)

echo "##### AC1 control on the base (expect: PermissionError, Could not start s_server, X25519 assertion)"
(cd /tmp/base && run python -m pytest "${AC1_TESTS[@]}" -k "not OnlineServer" -v -rfE -p no:cacheprovider)

echo "##### AC2 full suite after (fix branch)"
run python -m invoke test
run git status --porcelain

echo "##### AC2 full suite on the base"
(cd /tmp/base && run python -m invoke test)

exit 0
