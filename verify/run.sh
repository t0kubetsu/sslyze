#!/usr/bin/env bash
# Verification of fix/offline-cipher-suite-tests: the 4 moved tests with the network disabled (3 runs each, on dev + #734
# + the fix and on dev + the fix), negative controls, the 2 test directories with the network enabled (before/after),
# where the ~5 s of test_smtp are spent (with a control), ruff, and what Python's OpenSSL can offer. Each check prints its command and "exit=<code>"; the script ends with exit 0.
# Output of pytest and of external servers is printed with the prefix "  | ", so that no line of it can start with "::".
set -u

DEV_SHA=e175fff1e2d0f11a6696b7e2dc4203d4db92c902
PR734_SHA=bfb291ba2eccd9dad30c55985f466296eed9e979
UPSTREAM=https://github.com/nabla-c0d3/sslyze.git
FORK=https://github.com/t0kubetsu/sslyze.git
F=tests/plugins_tests/openssl_cipher_suites/test_openssl_cipher_suites_plugin.py
L=TestCipherSuitesPluginWithLocalServer
S=TestCipherSuitesPluginWithPythonTlsServer
MOVED_TESTS="$L::test_null_cipher_suites $L::test_rc4_cipher_suites $L::test_ecdsa_cipher_suites $S::test_smtp"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
PY=$(command -v python)

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}
q() { sed 's/^/  | /'; }
git_v() { git -c user.name=verify -c user.email=verify@invalid -c advice.detachedHead=false "$@"; }

echo "##### Versions and refs"
run "$NASSL_OPENSSL" version
"$PY" -c 'import importlib.metadata as m, json, ssl, sys; print(json.dumps({"python": sys.version.split()[0], "python_ssl": ssl.OPENSSL_VERSION, "nassl": m.version("nassl")}))'
echo "+ git fetch --unshallow origin; git fetch upstream dev and refs/pull/734/head; git fetch fork fix/offline-cipher-suite-tests"
git fetch -q --unshallow origin 2>&1 | q
git fetch -q --no-tags "$UPSTREAM" +refs/heads/dev:refs/remotes/up/dev +refs/pull/734/head:refs/remotes/up/pr734 2>&1 | q
git fetch -q --no-tags "$FORK" +refs/heads/fix/offline-cipher-suite-tests:refs/remotes/fork/fix 2>&1 | q
echo "exit=$?"
FIX_SHA=$(git rev-parse HEAD~1)
echo "upstream dev = $(git rev-parse up/dev) (expected $DEV_SHA)"
echo "#734 head    = $(git rev-parse up/pr734) (expected $PR734_SHA)"
echo "fix commit   = $FIX_SHA (HEAD~1 of this branch); fork fix/offline-cipher-suite-tests = $(git rev-parse fork/fix)"
echo "fix parent   = $(git rev-parse "$FIX_SHA~1")"
echo "+ git diff --stat HEAD~1 HEAD (the verification commit)"; git diff --stat HEAD~1 HEAD | q

echo
echo "##### Code states"
# before: dev and dev + #734; after: dev + fix and dev + #734 + fix
git_v worktree add -q --detach "$tmp/dev" "$DEV_SHA" && echo "state dev = $(git -C "$tmp/dev" rev-parse HEAD)"
git_v worktree add -q --detach "$tmp/dfix" "$FIX_SHA" && echo "state dev+fix = $(git -C "$tmp/dfix" rev-parse HEAD)"
git_v worktree add -q --detach "$tmp/d734" "$DEV_SHA" && git_v -C "$tmp/d734" merge -q --no-ff --no-edit "$PR734_SHA"
echo "state dev+#734 merge exit=$? head=$(git -C "$tmp/d734" rev-parse HEAD)"
git_v worktree add -q --detach "$tmp/d734fix" "$(git -C "$tmp/d734" rev-parse HEAD)" && git_v -C "$tmp/d734fix" merge -q --no-ff --no-edit "$FIX_SHA"
echo "state dev+#734+fix merge exit=$? head=$(git -C "$tmp/d734fix" rev-parse HEAD)"
for s in dev dfix d734 d734fix; do
  echo "state $s: tests/openssl_server/openssl-1-0-2-linux64 mode $(git -C "$tmp/$s" ls-files -s tests/openssl_server/openssl-1-0-2-linux64 | cut -c1-6)"
done

echo
echo "##### Trade-off 1: which of the expected suites Python's own OpenSSL can offer (PythonTlsServer uses it)"
cat > "$tmp/py_suites.py" <<'EOF'
import json
import ssl

suites = {
    "null": "AECDH-AES256-SHA:ADH-AES256-GCM-SHA384:ADH-AES256-SHA256:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:AECDH-AES128-SHA"
    ":ADH-AES128-GCM-SHA256:ADH-AES128-SHA256:ADH-AES128-SHA:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:ECDHE-RSA-NULL-SHA"
    ":AECDH-NULL-SHA:NULL-SHA256:NULL-SHA",
    "rc4": "ECDHE-RSA-RC4-SHA:RC4-SHA",
    "ecdsa": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384"
    ":ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA",
}
print(json.dumps({"python_ssl": ssl.OPENSSL_VERSION}))
for test, cipher_string in suites.items():
    unavailable = []
    for name in cipher_string.split(":"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.set_ciphers(f"{name}:@SECLEVEL=0")
        except ssl.SSLError:
            unavailable.append(name)
    total = len(cipher_string.split(":"))
    print(json.dumps({"test": test, "expected": total, "offerable": total - len(unavailable), "unavailable": unavailable}))
EOF
run "$PY" "$tmp/py_suites.py"

echo
echo "##### Negative-control plugin (changes the server or the client, never the test)"
mkdir -p "$tmp/controls"
cat > "$tmp/controls/cipher_controls.py" <<'EOF'
import importlib
import os
import smtplib

import pytest

_TEST_MODULE = "tests.plugins_tests.openssl_cipher_suites.test_openssl_cipher_suites_plugin"

_CIPHER_STRING_CHANGES = {
    "null_missing_suite": lambda s: s.replace(":ADH-SEED-SHA", ""),
    "rc4_missing_suite": lambda s: "RC4-SHA",
    "ecdsa_missing_suite": lambda s: s.replace(":ECDHE-ECDSA-DES-CBC3-SHA", ""),
}


def _smtp_server_rejecting_ehlo(self, client_socket):
    with client_socket.makefile("rb") as reader:
        client_socket.sendall(b"220 localhost ESMTP\r\n")
        reader.readline()
        client_socket.sendall(b"502 5.5.2 Command not recognized\r\n")
        raise OSError("control: EHLO rejected")


@pytest.fixture(autouse=True)
def _apply_cipher_control(monkeypatch):
    control = os.environ.get("CIPHER_CONTROL", "none")
    print(f"CIPHER_CONTROL={control}")
    if control == "none":
        return
    test_module = importlib.import_module(_TEST_MODULE)
    import tests.python_tls_server as python_tls_server

    if control in _CIPHER_STRING_CHANGES:
        change = _CIPHER_STRING_CHANGES[control]
        original_cls = test_module.LegacyOpenSslServer

        class _ChangedCipherServer(original_cls):
            def __init__(self, **kwargs):
                kwargs["openssl_cipher_string"] = change(kwargs["openssl_cipher_string"])
                print(f"control server cipher string: {kwargs['openssl_cipher_string']}")
                super().__init__(**kwargs)

        monkeypatch.setattr(test_module, "LegacyOpenSslServer", _ChangedCipherServer)
    elif control == "smtp_server_without_starttls":
        original_cls = test_module.PythonTlsServer

        class _NoStarttlsServer(original_cls):
            def __init__(self, **kwargs):
                kwargs["should_do_smtp_starttls"] = False
                super().__init__(**kwargs)

        monkeypatch.setattr(test_module, "PythonTlsServer", _NoStarttlsServer)
    elif control == "smtp_server_rejects_ehlo":
        monkeypatch.setattr(python_tls_server.PythonTlsServer, "_do_smtp_starttls", _smtp_server_rejecting_ehlo)
    elif control == "smtp_client_skips_ehlo":
        # The client sends HELO instead of EHLO; has_extn() is forced so that only the server decides
        monkeypatch.setattr(smtplib.SMTP, "ehlo", lambda self, name="": self.helo(name))
        monkeypatch.setattr(smtplib.SMTP, "has_extn", lambda self, opt: True)
    elif control == "smtp_client_skips_starttls":
        # The client sends NOOP instead of STARTTLS
        original_docmd = smtplib.SMTP.docmd
        monkeypatch.setattr(
            smtplib.SMTP,
            "docmd",
            lambda self, cmd, args="": original_docmd(self, "NOOP" if cmd.upper() == "STARTTLS" else cmd, args),
        )
    else:
        raise ValueError(f"Unknown control {control}")
EOF
echo "written: $tmp/controls/cipher_controls.py"

# The part that runs without network: executed in a new network namespace that has only a loopback interface
cat > "$tmp/offline.sh" <<'EOF'
set -u
tmp=$1
PY=$2
F=$3
MOVED_TESTS=$4
L=TestCipherSuitesPluginWithLocalServer
S=TestCipherSuitesPluginWithPythonTlsServer
q() { sed 's/^/  | /'; }

echo "+ ip -brief address (inside the namespace)"; ip -brief address | q
echo "+ network check: DNS lookup of github.com, TCP to 140.82.112.3:443 and 1.1.1.1:443, TCP to a local listener"
"$PY" - <<'PYEOF'
import json, socket
out = {}
try:
    out["dns_github.com"] = socket.getaddrinfo("github.com", 443)[0][4][0]
except OSError as e:
    out["dns_github.com"] = f"FAILED {type(e).__name__}: {e}"
for ip in ("140.82.112.3", "1.1.1.1"):
    try:
        socket.create_connection((ip, 443), timeout=5).close()
        out[f"tcp_{ip}"] = "CONNECTED"
    except OSError as e:
        out[f"tcp_{ip}"] = f"FAILED {type(e).__name__}: {e}"
server = socket.create_server(("127.0.0.1", 0))
try:
    socket.create_connection(server.getsockname(), timeout=5).close()
    out["tcp_loopback"] = "CONNECTED"
except OSError as e:
    out["tcp_loopback"] = f"FAILED {type(e).__name__}: {e}"
print(json.dumps(out))
PYEOF
echo "exit=$?"

for state in d734fix dfix; do
  echo
  echo "##### Offline: the 4 moved tests, 3 runs each, state $state ($(git -C "$tmp/$state" rev-parse HEAD))"
  cd "$tmp/$state" || continue
  PYTHONPATH="$PWD" "$PY" -c 'import json, sslyze; print(json.dumps({"sslyze_from": sslyze.__file__}))'
  for i in 1 2 3; do
    for t in $MOVED_TESTS; do
      start=$(date +%s%N)
      PYTHONPATH="$PWD" timeout 600 "$PY" -m pytest "$F::$t" -p no:cacheprovider -q -rA --tb=line > "$tmp/out.txt" 2>&1
      rc=$?
      end=$(date +%s%N)
      echo "RESULT state=$state run=$i test=${t#*::} exit=$rc wall_ms=$(( (end - start) / 1000000 ))"
      grep -E '^(PASSED|FAILED|ERROR|SKIPPED) |[0-9]+ (passed|failed|error|skipped)' "$tmp/out.txt" | q
      [ "$rc" -ne 0 ] && grep -E '^E |Error' "$tmp/out.txt" | head -15 | q
    done
  done
done

echo
echo "##### Offline: negative controls, state d734fix"
cd "$tmp/d734fix" || exit 0
while read -r control test; do
  echo "+ CIPHER_CONTROL=$control python -m pytest -p cipher_controls $F::$test"
  CIPHER_CONTROL=$control PYTHONPATH="$tmp/controls:$PWD" timeout 600 "$PY" -m pytest "$F::$test" -p cipher_controls \
    -p no:cacheprovider -q -rA --tb=line > "$tmp/out.txt" 2>&1
  rc=$?
  grep -E "^(CIPHER_CONTROL|control server)|^E |AssertionError|^(PASSED|FAILED|ERROR) |[0-9]+ (passed|failed)" "$tmp/out.txt" | head -20 | q
  echo "CONTROL $control exit=$rc"
done <<CEOF
none $L::test_null_cipher_suites
null_missing_suite $L::test_null_cipher_suites
none $L::test_rc4_cipher_suites
rc4_missing_suite $L::test_rc4_cipher_suites
none $L::test_ecdsa_cipher_suites
ecdsa_missing_suite $L::test_ecdsa_cipher_suites
none $S::test_smtp
smtp_server_without_starttls $S::test_smtp
smtp_server_rejects_ehlo $S::test_smtp
smtp_client_skips_ehlo $S::test_smtp
smtp_client_skips_starttls $S::test_smtp
CEOF
EOF

echo
echo "##### Offline part: sudo unshare --net, loopback up, then back to $(id -un) with setpriv"
echo "+ sudo unshare --net -- sh -c 'ip link set lo up && exec setpriv --reuid=$(id -u) --regid=$(id -g) --init-groups -- env PATH=... HOME=... bash $tmp/offline.sh ...'"
sudo unshare --net -- sh -c 'ip link set lo up && exec setpriv --reuid="$1" --regid="$2" --init-groups -- env PATH="$3" HOME="$4" bash "$5" "$6" "$7" "$8" "$9"' \
  sh "$(id -u)" "$(id -g)" "$PATH" "$HOME" "$tmp/offline.sh" "$tmp" "$PY" "$F" "$MOVED_TESTS"
echo "exit=$?"

echo
echo "##### Online: the 2 test directories, before and after, network enabled"
for state in d734 d734fix dev dfix; do
  cd "$tmp/$state" || continue
  echo "+ [state $state $(git rev-parse HEAD)] python -m pytest tests/plugins_tests/openssl_cipher_suites/ tests/plugins_tests/certificate_info/"
  start=$(date +%s)
  PYTHONPATH="$PWD" timeout 3600 "$PY" -m pytest tests/plugins_tests/openssl_cipher_suites/ tests/plugins_tests/certificate_info/ \
    -p no:cacheprovider -q -rA --tb=line > "$tmp/out.txt" 2>&1
  rc=$?
  grep -E '^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS) |^=+ .*(passed|failed|error).* =+$|^E ' "$tmp/out.txt" | q
  echo "DIRS state=$state exit=$rc wall_s=$(( $(date +%s) - start ))"
done

echo
echo "##### Where the ~5 s of test_smtp are spent, state d734fix (PythonTlsServer on 127.0.0.1 only)"
SMTP_TEST="$F::$S::test_smtp"
SNI_TEST=tests/plugins_tests/certificate_info/test_certificate_info_plugin.py::TestCertificateInfoPlugin::test_sni_sent_has_non_unicode_characters
mkdir -p "$tmp/timing"
cat > "$tmp/timing/exit_timing.py" <<'EOF'
"""Times PythonTlsServer.__enter__, the body of the with block, and the 2 steps of __exit__ (close, then join).

The replacement __exit__ runs the same 2 steps as the original one. EXIT_TIMING_CONTROL=shutdown also calls
shutdown(SHUT_RDWR) on the listening socket before close() (control).
"""

import os
import socket
import sys
import time

import pytest

from tests.python_tls_server import PythonTlsServer


def _log(msg):
    sys.__stdout__.write("TIMING " + msg + "\n")
    sys.__stdout__.flush()


_original_enter = PythonTlsServer.__enter__


def _enter(self):
    t0 = time.perf_counter()
    result = _original_enter(self)
    _log(f"__enter__ {time.perf_counter() - t0:.3f}s")
    self._timing_entered = time.perf_counter()
    return result


def _exit(self, *args):
    t_start = time.perf_counter()
    _log(f"body_inside_with (connectivity check + scan) {t_start - self._timing_entered:.3f}s")
    if os.environ.get("EXIT_TIMING_CONTROL") == "shutdown":
        self._listening_socket.shutdown(socket.SHUT_RDWR)
        _log("control: shutdown(SHUT_RDWR) called before close()")
    t0 = time.perf_counter()
    self._listening_socket.close()
    t1 = time.perf_counter()
    _log(f"__exit__ close() {t1 - t0:.3f}s; accept thread alive after close: {self._accept_thread.is_alive()}")
    self._accept_thread.join(timeout=5)
    t2 = time.perf_counter()
    _log(f"__exit__ join(timeout=5) {t2 - t1:.3f}s; accept thread alive after join: {self._accept_thread.is_alive()}")
    _log(f"__exit__ total {t2 - t_start:.3f}s")


PythonTlsServer.__enter__ = _enter
PythonTlsServer.__exit__ = _exit


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    t0 = time.perf_counter()
    yield
    _log(f"{item.name} call total {time.perf_counter() - t0:.3f}s")
EOF
cd "$tmp/d734fix" || exit 0
echo "+ [state d734fix $(git rev-parse HEAD)] A. python -m pytest -p no:cacheprovider -q --durations=0 --durations-min=0 $SMTP_TEST $SNI_TEST"
PYTHONPATH="$PWD" timeout 600 "$PY" -m pytest -p no:cacheprovider -q --durations=0 --durations-min=0 "$SMTP_TEST" "$SNI_TEST" 2>&1 \
  | grep -E '^[0-9.]+s (setup|call|teardown) |[0-9]+ (passed|failed)' | q
echo "TIMING_A exit=${PIPESTATUS[0]}"
for i in 1 2 3; do
  echo "+ B$i. python -m pytest -p no:cacheprovider -q -s -p exit_timing $SMTP_TEST $SNI_TEST"
  PYTHONPATH="$tmp/timing:$PWD" timeout 600 "$PY" -m pytest -p no:cacheprovider -q -s -p exit_timing "$SMTP_TEST" "$SNI_TEST" 2>&1 \
    | grep -E 'TIMING|[0-9]+ (passed|failed)' | q
  echo "TIMING_B$i exit=${PIPESTATUS[0]}"
done
echo "+ C. EXIT_TIMING_CONTROL=shutdown python -m pytest -p no:cacheprovider -q -s -p exit_timing $SMTP_TEST $SNI_TEST"
EXIT_TIMING_CONTROL=shutdown PYTHONPATH="$tmp/timing:$PWD" timeout 600 "$PY" -m pytest -p no:cacheprovider -q -s -p exit_timing \
  "$SMTP_TEST" "$SNI_TEST" 2>&1 | grep -E 'TIMING|[0-9]+ (passed|failed)' | q
echo "TIMING_C exit=${PIPESTATUS[0]}"
echo "+ git status --porcelain (d734fix)"; git status --porcelain | q; echo "porcelain_lines=$(git status --porcelain | wc -l)"

echo
echo "##### ruff (requirements-dev.txt)"
cd "$tmp/dfix" || exit 0
run ruff --version
echo "+ ruff check (fix)"; ruff check 2>&1 | q; echo "exit=${PIPESTATUS[0]}"
echo "+ ruff check --ignore EXE002 (fix)"; ruff check --ignore EXE002 2>&1 | q; echo "exit=${PIPESTATUS[0]}"
echo "+ ruff format --check (fix)"; ruff format --check 2>&1 | q; echo "exit=${PIPESTATUS[0]}"
CHANGED="tests/python_tls_server.py $F"
echo "+ ruff check $CHANGED (fix)"; ruff check $CHANGED 2>&1 | q; echo "exit=${PIPESTATUS[0]}"
echo "+ ruff format --check $CHANGED (fix)"; ruff format --check $CHANGED 2>&1 | q; echo "exit=${PIPESTATUS[0]}"
echo "+ ruff check (dev, baseline)"; (cd "$tmp/dev" && ruff check 2>&1 | tail -1 | q; echo "exit=${PIPESTATUS[0]}")
echo "+ git status --porcelain (fix)"; git status --porcelain | q; echo "porcelain_lines=$(git status --porcelain | wc -l)"

exit 0
