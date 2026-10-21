#!/usr/bin/env bash
# Analysis of 4 online tests of TestCipherSuitesPluginWithOnlineServer on 9 code states and on "release".
# Every check prints its command and "exit=<code>". Output that comes from external servers or from pytest
# is printed with the prefix "  | ", so that no line of it can start with "::".
set -u

DEV_SHA=e175fff1e2d0f11a6696b7e2dc4203d4db92c902
UPSTREAM=https://github.com/nabla-c0d3/sslyze.git
FORK=https://github.com/t0kubetsu/sslyze.git
# PR number, fork branch, expected head
PRS=(
  "734 fix/dev-test-suite bfb291ba2eccd9dad30c55985f466296eed9e979"
  "735 fix/732-plugin-crashes d666bf62ddb4311eb3f27fd19c7c1781f169b0b8"
  "736 fix/722-brainpool-tls13 679bfa4d6bb9d3d5efa6995b14182b1635c4369e"
  "737 fix/700-pq-only-server 1fdfb3ecbb07d01ca1652c3031eac1e7f8b7637c"
  "738 fix/719-ech-retry-config a373adf60af9ea89055ee9d01d6e508400ab2f57"
  "739 fix/mozilla-tls-curves b6f6217aded5115e561e258582056ef6c2f5d3c7"
)
TEST_FILE=tests/plugins_tests/openssl_cipher_suites/test_openssl_cipher_suites_plugin.py
TEST_CLASS=TestCipherSuitesPluginWithOnlineServer
TESTS=(test_null_cipher_suites test_rc4_cipher_suites test_ecdsa_cipher_suites test_smtp)
RUNS=3

srv=
tmp=$(mktemp -d)
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null; rm -rf "$tmp"' EXIT
REPO=$PWD
PY=$(command -v python)

run() {
  echo "+ $*"
  "$@"
  echo "exit=$?"
}

# Prefix external text so that no line can start with "::"
q() { sed 's/^/  | /'; }

git_v() { git -c user.name=verify -c user.email=verify@invalid -c advice.detachedHead=false "$@"; }

echo "##### Versions and refs"
run git rev-parse HEAD
run "$NASSL_OPENSSL" version
run python -c 'import importlib.metadata as m, nassl; print("nassl", m.version("nassl"), nassl.__file__)'
echo "+ git ls-remote $UPSTREAM refs/heads/dev refs/heads/release"
git ls-remote "$UPSTREAM" refs/heads/dev refs/heads/release
echo "exit=$?"
echo "+ git fetch (full history of $FORK fix/* branches, then upstream dev and release)"
git fetch -q --no-tags --unshallow "$FORK" '+refs/heads/fix/*:refs/remotes/fork/fix/*' \
  && git fetch -q --no-tags "$UPSTREAM" '+refs/heads/dev:refs/remotes/up/dev' '+refs/heads/release:refs/remotes/up/release'
echo "exit=$?"
echo "upstream dev     = $(git rev-parse up/dev) (expected $DEV_SHA)"
echo "upstream release = $(git rev-parse up/release)"
for pr in "${PRS[@]}"; do
  set -- $pr
  echo "#$1 $2 = $(git rev-parse "fork/$2") (expected $3)"
done

# ---------------------------------------------------------------------------------------------------------------
echo
echo "##### Part 1: the 4 servers today, measured with OpenSSL 4 (\$NASSL_OPENSSL) and OpenSSL 1.0.2"
# OpenSSL 1.0.2 = the binary of sslyze's own legacy test server; it can still offer the NULL, anon and RC4 suites
OLD_OPENSSL="$tmp/openssl-1-0-2"
cp "$REPO/tests/openssl_server/openssl-1-0-2-linux64" "$OLD_OPENSSL" && chmod +x "$OLD_OPENSSL"
run "$OLD_OPENSSL" version

echo "+ $NASSL_OPENSSL ciphers -v 'NULL:aNULL:RC4:ECDSA:@SECLEVEL=0'  (the test-relevant suites that OpenSSL 4 can offer)"
"$NASSL_OPENSSL" ciphers -v 'NULL:aNULL:RC4:ECDSA:@SECLEVEL=0' 2>&1 | q
echo "exit=${PIPESTATUS[0]}"
echo "+ $OLD_OPENSSL ciphers -v 'NULL:aNULL:RC4:ECDSA'"
"$OLD_OPENSSL" ciphers -v 'NULL:aNULL:RC4:ECDSA' 2>&1 | q
echo "exit=${PIPESTATUS[0]}"

# One handshake; prints ACCEPTED/REJECTED. $1=openssl $2=host $3=port $4=starttls(none|smtp) rest=s_client options
handshake() {
  local bin=$1 host=$2 port=$3 starttls=$4
  shift 4
  local st=()
  [ "$starttls" = smtp ] && st=(-starttls smtp)
  timeout 15 "$bin" s_client -connect "$host:$port" -servername "$host" "${st[@]}" "$@" < /dev/null > "$tmp/hs.txt" 2>&1
  local rc=$?
  # A completed handshake prints "New, ..., Cipher is <name>"; a failed one prints "Cipher is (NONE)".
  # The negotiated version is the "Protocol  :" line of the SSL-Session block (the "New," line gives the cipher's version)
  if grep -q -E '^New, .*Cipher is [A-Za-z0-9_-]+$' "$tmp/hs.txt"; then
    echo "ACCEPTED rc=$rc protocol=$(sed -n -E 's/^ *Protocol *: *//p' "$tmp/hs.txt" | head -1) cipher=$(sed -n -E 's/^ *Cipher *: *//p' "$tmp/hs.txt" | head -1)"
  else
    echo "REJECTED rc=$rc"
  fi
}

# $1=label $2=openssl binary $3=host $4=port $5=starttls
enumerate() {
  local label=$1 bin=$2 host=$3 port=$4 starttls=$5 v c res sl=':@SECLEVEL=0'
  "$bin" version | grep -q '^OpenSSL 1\.' && sl=''
  echo "--- [$label] $host:$port starttls=$starttls"
  echo "+ timeout 10 bash -c '</dev/tcp/$host/$port'"
  timeout 10 bash -c "</dev/tcp/$host/$port" 2>&1 | q
  echo "tcp_connect_exit=${PIPESTATUS[0]}"
  for v in tls1 tls1_1 tls1_2 tls1_3; do
    if [ "$v" = tls1_3 ]; then
      if [ -n "$sl" ]; then res=$(handshake "$bin" "$host" "$port" "$starttls" -tls1_3); else res="n/a (OpenSSL 1.0.2 has no TLS 1.3)"; fi
    else
      res=$(handshake "$bin" "$host" "$port" "$starttls" -$v -cipher "ALL:COMPLEMENTOFALL$sl")
    fi
    echo "[$label] $host version $v: $res"
  done
  local n_acc=0 n_rej=0
  for c in $("$bin" ciphers "ALL:COMPLEMENTOFALL$sl" 2>/dev/null | tr ':' ' '); do
    # TLS 1.3 suite names are not valid for -cipher
    case "$c" in TLS_AES_*|TLS_CHACHA20_*) continue ;; esac
    res=$(handshake "$bin" "$host" "$port" "$starttls" -tls1_2 -cipher "$c$sl")
    case "$res" in
      ACCEPTED*) n_acc=$((n_acc+1)); echo "[$label] $host tls1_2 suite $c: $res" ;;
      *) n_rej=$((n_rej+1)) ;;
    esac
  done
  echo "[$label] $host tls1_2 suites: accepted=$n_acc rejected=$n_rej"
}

# Control: a local server that accepts exactly one TLS 1.2 suite. Each enumeration must report exactly that suite.
echo "--- control: local s_server with -cipher ECDHE-RSA-AES128-SHA only"
echo "+ $NASSL_OPENSSL s_server -tls1_2 -cipher ECDHE-RSA-AES128-SHA -cert tests/server_certificates/rsa/server-rsa-cert.pem -key tests/server_certificates/rsa/server-rsa-key.pem -accept 127.0.0.1:44433 -www"
"$NASSL_OPENSSL" s_server -tls1_2 -cipher ECDHE-RSA-AES128-SHA -cert "$REPO/tests/server_certificates/rsa/server-rsa-cert.pem" \
  -key "$REPO/tests/server_certificates/rsa/server-rsa-key.pem" -accept 127.0.0.1:44433 -www > "$tmp/s_server.log" 2>&1 &
srv=$!
for _ in $(seq 50); do grep -q '^ACCEPT' "$tmp/s_server.log" && break; sleep 0.2; done
grep -q '^ACCEPT' "$tmp/s_server.log" && echo "s_server ready" || echo "s_server NOT ready"
enumerate control-openssl4 "$NASSL_OPENSSL" 127.0.0.1 44433 none
enumerate control-openssl-1.0.2 "$OLD_OPENSSL" 127.0.0.1 44433 none
kill "$srv"; wait "$srv" 2>/dev/null; srv=

for target in null.badssl.com:443:none rc4.badssl.com:443:none ecc256.badssl.com:443:none smtp.gmail.com:587:smtp; do
  IFS=: read -r h p s <<< "$target"
  echo "+ getent ahosts $h"
  getent ahosts "$h" | awk '{print $1}' | sort -u | q
  echo "exit=${PIPESTATUS[0]}"
  enumerate openssl4 "$NASSL_OPENSSL" "$h" "$p" "$s"
  enumerate openssl-1.0.2 "$OLD_OPENSSL" "$h" "$p" "$s"
done

# ---------------------------------------------------------------------------------------------------------------
echo
echo "##### Part 2: build the code states (one worktree each)"
WT=$tmp/wt
mkdir -p "$WT"
STATES=()
add_state() { # $1=name $2..=fork branches to merge on top of dev, in order
  local name=$1 b
  shift
  echo "--- state $name"
  git_v worktree add -q --detach "$WT/$name" "$DEV_SHA" || { echo "worktree exit=$?"; return; }
  for b in "$@"; do
    echo "+ git merge --no-ff --no-edit fork/$b"
    (cd "$WT/$name" && git_v merge -q --no-ff --no-edit "fork/$b" > /dev/null 2>&1)
    echo "exit=$?"
  done
  echo "state $name HEAD=$(git -C "$WT/$name" rev-parse HEAD)"
  echo "state $name commits on top of dev $DEV_SHA (git log --format='%h %s' $DEV_SHA..HEAD):"
  git -C "$WT/$name" log --format='%h %s' "$DEV_SHA..HEAD" | q
  echo "state $name sslyze/ files changed vs dev:"
  git -C "$WT/$name" diff --stat "$DEV_SHA" HEAD -- sslyze/ | q
  STATES+=("$name")
}
add_state 1-dev
add_state 2-dev+734 fix/dev-test-suite
add_state 3-dev+734+735 fix/dev-test-suite fix/732-plugin-crashes
add_state 3-dev+734+736 fix/dev-test-suite fix/722-brainpool-tls13
add_state 3-dev+734+737 fix/dev-test-suite fix/700-pq-only-server
add_state 3-dev+734+738 fix/dev-test-suite fix/719-ech-retry-config
add_state 3-dev+734+739 fix/dev-test-suite fix/mozilla-tls-curves
add_state 4-dev+734..739 fix/dev-test-suite fix/732-plugin-crashes fix/722-brainpool-tls13 fix/700-pq-only-server fix/719-ech-retry-config fix/mozilla-tls-curves

echo "--- reference: release with nassl 5.4.0 from PyPI, in its own venv"
git_v worktree add -q --detach "$WT/release" up/release
echo "state release HEAD=$(git -C "$WT/release" rev-parse HEAD) ($(git -C "$WT/release" log -1 --format='%s'))"
run python -m venv "$tmp/vrel"
run "$tmp/vrel/bin/python" -m pip install -q nassl==5.4.0 "$WT/release" pytest faker

# Proof of the code each state imports
for name in "${STATES[@]}"; do
  echo "+ [$name] import check"
  (cd "$WT/$name" && PYTHONPATH="$WT/$name" "$PY" -c 'import importlib.metadata as m, nassl, sslyze; print("nassl", m.version("nassl"), "sslyze from", sslyze.__file__)' 2>&1)
  echo "exit=$?"
done
echo "+ [release] import check"
(cd "$WT/release" && PYTHONPATH="$WT/release" "$tmp/vrel/bin/python" -c 'import importlib.metadata as m, nassl, sslyze; print("nassl", m.version("nassl"), "sslyze from", sslyze.__file__)' 2>&1)
echo "exit=$?"

# ---------------------------------------------------------------------------------------------------------------
echo
echo "##### Part 2b: connectivity check alone (check_connectivity_to_server), once per state and host"
cat > "$tmp/conn.py" <<'EOF'
import json
import sys

from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from sslyze.server_connectivity import check_connectivity_to_server
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation

host, port, starttls = sys.argv[1], int(sys.argv[2]), sys.argv[3]
location = ServerNetworkLocation(host, port)
if starttls == "smtp":
    config = ServerNetworkConfiguration(
        tls_server_name_indication=host, tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP
    )
else:
    config = ServerNetworkConfiguration.default_for_server_location(location)
try:
    result = check_connectivity_to_server(server_location=location, network_configuration=config)
    print("CONNECTIVITY ok", json.dumps({"tls": result.highest_tls_version_supported.name, "cipher": result.cipher_suite_supported}))
except Exception as e:
    print("CONNECTIVITY error", type(e).__name__, json.dumps(str(e)))
EOF
for name in "${STATES[@]}" release; do
  py=$PY
  [ "$name" = release ] && py="$tmp/vrel/bin/python"
  for target in null.badssl.com:443:none rc4.badssl.com:443:none ecc256.badssl.com:443:none smtp.gmail.com:587:smtp; do
    IFS=: read -r h p s <<< "$target"
    echo "+ [$name] (cd $name && PYTHONPATH=. python conn.py $h $p $s)"
    out=$(cd "$WT/$name" && PYTHONPATH="$WT/$name" timeout 300 "$py" "$tmp/conn.py" "$h" "$p" "$s" 2>&1)
    rc=$?
    echo "$out" | q
    echo "exit=$rc"
    echo "CONN state=$name host=$h $(echo "$out" | grep -m1 -o -E '^CONNECTIVITY (ok|error [A-Za-z]+)' || echo 'CONNECTIVITY missing')"
  done
done

# ---------------------------------------------------------------------------------------------------------------
echo
echo "##### Part 3: the 4 tests, $RUNS runs. Within a run, the states follow each other, so that the states of one"
echo "##### run are measured close together in time."
ids=()
for t in "${TESTS[@]}"; do ids+=("$TEST_FILE::$TEST_CLASS::$t"); done

# $1=run $2=state $3=dir $4=python
run_tests() {
  local r=$1 name=$2 dir=$3 py=$4 t st
  echo "--- run $r state $name start=$(date -u +%H:%M:%S)"
  echo "+ (cd $dir && PYTHONPATH=$dir timeout 1500 $py -m pytest -p no:cacheprovider -rA --tb=short -q <the 4 tests>)"
  (cd "$dir" && PYTHONPATH="$dir" timeout 1500 "$py" -m pytest -p no:cacheprovider -rA --tb=short -q "${ids[@]}") > "$tmp/pytest.txt" 2>&1
  echo "exit=$?"
  q < "$tmp/pytest.txt"
  for t in "${TESTS[@]}"; do
    st=$(grep -o -E "^(PASSED|FAILED|ERROR) [^ ]*::$t( |$)" "$tmp/pytest.txt" | head -1 | cut -d' ' -f1)
    echo "RESULT run=$r state=$name test=$t result=${st:-MISSING}" | tee -a "$tmp/results.txt"
  done
  echo "--- run $r state $name end=$(date -u +%H:%M:%S)"
}

for r in $(seq "$RUNS"); do
  for name in "${STATES[@]}"; do
    run_tests "$r" "$name" "$WT/$name" "$PY"
  done
  run_tests "$r" release "$WT/release" "$tmp/vrel/bin/python"
done

echo
echo "##### Summary: all RESULT lines, grouped by test"
for t in "${TESTS[@]}"; do
  echo "--- $t"
  grep " test=$t " "$tmp/results.txt"
done

for name in "${STATES[@]}" release; do git_v worktree remove --force "$WT/$name"; done
exit 0
