#!/usr/bin/env bash
# Runs in a disposable root Linux container containing the native controller binary.
set -Eeuo pipefail
readonly controller=/usr/local/bin/rentnerproxy-controller
readonly control=/run/rentnerproxy/crowdsec
readonly state=/var/lib/rentnerproxy/crowdsec
readonly fixture=/tmp/rentnerproxy-native-crowdsec
[[ $(id -u) == 0 && -x $controller && -x /crowdsec-fixture && ! -e $control && ! -e $state && ! -e $fixture ]]
for target in /usr/local/bin/{gosu,cscli,crowdsec}; do [[ ! -e $target ]]; done
install -d -m 0700 -o 10001 -g 10001 "$control"
install -d -m 0700 /run/rentnerproxy/crowdsec-supervisor /var/lib/rentnerproxy/crowdsec-supervisor
install -d -m 0711 "$state"
install -d -m 0700 -o 10003 -g 10003 "$state/credentials" "$fixture"
install -d -m 0710 -o 0 -g 10001 "$state/bouncer"
printf '%064d\n' 0 > "$state/bouncer/caddy-bouncer-key"
chown 0:10001 "$state/bouncer/caddy-bouncer-key"
chmod 0440 "$state/bouncer/caddy-bouncer-key"
cat > /usr/local/bin/gosu <<'SH'
#!/bin/sh
[ "$1" = crowdsec ] || exit 10
shift
exec setpriv --reuid=10003 --regid=10003 --clear-groups -- "$@"
SH
cat > /usr/local/bin/cscli <<'SH'
#!/bin/sh
set -eu
[ "$(id -u):$(id -g)" = 10003:10003 ]
[ -z "${SMTP_PASSWORD+x}" ] || exit 12
[ -z "${SMTP_USER+x}" ] || exit 12
[ "$1" = -c ]
shift 2
case "$*" in
    'machines list -o json') printf '[{"machineId":"rentnerproxy-managed"}]\n' ;;
    'bouncers delete rentnerproxy-caddy') ;;
    'bouncers add rentnerproxy-caddy -o raw') head -c 32 /dev/urandom | base64 | tr -d '=\n' ;;
    'capi register -f '*)
        if [ -e /tmp/rentnerproxy-native-crowdsec/fail-registration ]; then
            echo partial > "$4"
            rm /tmp/rentnerproxy-native-crowdsec/fail-registration
            exit 1
        fi
        echo fixture > "$4" ;;
    'capi status')
        if [ -e /tmp/rentnerproxy-native-crowdsec/fail-probe ]; then
            rm /tmp/rentnerproxy-native-crowdsec/fail-probe
            exit 1
        fi ;;
    '-o json console status')
        if [ -e /tmp/rentnerproxy-native-crowdsec/hold-probe ]; then
            echo ready > /tmp/rentnerproxy-native-crowdsec/probing
            while [ -e /tmp/rentnerproxy-native-crowdsec/hold-probe ]; do sleep 0.05; done
        fi
        echo '{"console":{"authenticated":true,"enrolled":true}}' ;;
    'console enroll --disable all -- -DEMO_0123456789-ab') echo called >> /tmp/rentnerproxy-native-crowdsec/enrollments ;;
    *) exit 11 ;;
esac
SH
cat > /usr/local/bin/crowdsec <<'SH'
#!/bin/sh
set -eu
[ "$(id -u):$(id -g)" = 10003:10003 ]
[ -z "${SMTP_PASSWORD+x}" ] || exit 12
[ -z "${SMTP_USER+x}" ] || exit 12
if [ "$1" = -t ]; then
    if [ -e /tmp/rentnerproxy-native-crowdsec/interrupt-validation ]; then
        rm /tmp/rentnerproxy-native-crowdsec/interrupt-validation
        kill -TERM "$$"
    fi
    if [ "$3" = /usr/share/rentnerproxy/crowdsec/config-online.yaml ]; then
        [ ! -e /tmp/rentnerproxy-native-crowdsec/invalid-online ] || exit 1
        if [ -e /tmp/rentnerproxy-native-crowdsec/hold-validation ]; then
            echo ready > /tmp/rentnerproxy-native-crowdsec/validating
            while [ -e /tmp/rentnerproxy-native-crowdsec/hold-validation ]; do sleep 0.05; done
        fi
    fi
    if [ -e /tmp/rentnerproxy-native-crowdsec/invalid-config ]; then exit 1; fi
    exit 0
fi
echo "$$" > /tmp/rentnerproxy-native-crowdsec/engine.pid
echo "$*" >> /tmp/rentnerproxy-native-crowdsec/launches
exec /crowdsec-fixture
SH
chmod 0755 /usr/local/bin/{cscli,crowdsec,gosu}
mode() { printf '%s\n' "$1" > "$control/desired-mode"; chown 10001:10001 "$control/desired-mode"; chmod 0600 "$control/desired-mode"; }
until_match() {
    local file=$1 pattern=$2 attempt
    for ((attempt=0; attempt<110; attempt++)); do
        if [[ -f $file ]] && grep -Eq "$pattern" "$file"; then return; fi
        kill -0 "$supervisor" || return 1
        sleep 0.1
    done
    printf 'FAIL: expected %s in %s\n' "$pattern" "$file" >&2
    exit 1
}
stop_supervisor() {
    local attempt engine_pid=''
    if [[ -f $fixture/engine.pid ]]; then read -r engine_pid < "$fixture/engine.pid"; fi
    kill -TERM "$supervisor" 2>/dev/null || :
    for ((attempt=0; attempt<150; attempt++)); do
        if ! kill -0 "$supervisor" 2>/dev/null; then wait "$supervisor"; return; fi
        sleep 0.1
    done
    if [[ $engine_pid =~ ^[1-9][0-9]*$ && -r /proc/$engine_pid/status ]] &&
        grep -Eq "^PPid:[[:space:]]+$supervisor$" "/proc/$engine_pid/status"; then
        kill -KILL "$engine_pid" 2>/dev/null || :
    fi
    kill -KILL "$supervisor" 2>/dev/null || :
    for ((attempt=0; attempt<20; attempt++)); do
        if ! kill -0 "$supervisor" 2>/dev/null; then wait "$supervisor" || :; break; fi
        sleep 0.1
    done
    printf 'FAIL: CrowdSec supervisor exceeded its shutdown deadline\n' >&2
    return 1
}
mode stopped
touch "$fixture/interrupt-validation" "$fixture/fail-registration" "$state/credentials/console.yaml"
export SMTP_USER=dummy SMTP_PASSWORD=dummy
"$controller" --appliance-supervisor crowdsec &
supervisor=$!
trap 'stop_supervisor || exit 1' EXIT
until_match "$control/status.json" '"state":"stopped"'
mode managed
until_match "$control/status.json" '"restarts":1.*"state":"ready"'
readonly key="$state/bouncer/caddy-bouncer-key"
[[ $(stat -c '%u:%g:%a:%h' "$key") == 0:10001:440:1 && $(stat -c '%u:%g:%a' "$control/status.json") == 0:10001:440 ]]
first=$(<"$key")
until_match "$fixture/launches" 'config.yaml -no-capi'
capi="$state/credentials/online_api_credentials.yaml"
mode managed-online
until_match "$control/status.json" '"community":"degraded".*"state":"ready"'
[[ ! -e $capi ]]
mode managed
until_match "$control/status.json" '"community":"disabled".*"state":"ready"'
touch "$fixture/fail-probe"
mode managed-online
until_match "$control/status.json" '"community":"degraded".*"state":"ready"'
[[ $(<"$capi") == fixture ]]
registered=$(stat -c '%d:%i' "$capi")
local_engine=$(<"$fixture/engine.pid")
mode managed
until_match "$control/status.json" '"community":"disabled".*"state":"ready"'
touch "$fixture/invalid-online"
mode managed-online
until_match "$control/status.json" '"community":"degraded".*"state":"ready"'
[[ $(<"$fixture/engine.pid") == "$local_engine" ]]
kill -0 "$local_engine"
rm "$fixture/invalid-online"
mode managed
until_match "$control/status.json" '"community":"disabled".*"state":"ready"'
mode managed-online
until_match "$control/status.json" '"community":"connected".*"console":"connected"'
[[ $(stat -c '%d:%i' "$capi") == "$registered" && $(<"$capi") == fixture ]]
[[ $(<"$key") == "$first" ]]
until_match "$fixture/launches" 'config-online.yaml$'
[[ $(stat -c '%u:%g:%a:%h' "$capi") == 10003:10003:600:1 ]]
id=0123456789abcdef0123456789abcdef
queue_enrollment() {
    printf '%s\n%s\n' "$id" -DEMO_0123456789-ab > "$fixture/request"
    chown 10001:10001 "$fixture/request"
    chmod 0600 "$fixture/request"
    mv "$fixture/request" "$control/console-enrollment-request"
}
queue_enrollment
until_match "$control/console-enrollment-result.json" '"state":"pending"'
mode managed
until_match "$control/status.json" '"community":"disabled".*"state":"ready"'
touch "$fixture/hold-probe"
mode managed-online
until_match "$fixture/probing" '^ready$'
queue_enrollment
mode managed
rm "$fixture/hold-probe"
until_match "$control/console-enrollment-result.json" '"state":"failed"'
until_match "$control/status.json" '"community":"disabled".*"state":"ready"'
[[ $(wc -l < "$fixture/enrollments") -eq 1 ]]
mode managed-online
until_match "$control/status.json" '"community":"connected".*"console":"connected"'
kill -TERM "$(<"$fixture/engine.pid")"
until_match "$control/status.json" '"community":"degraded".*"console":"degraded".*"state":"ready"'
[[ $(<"$key") == "$first" ]]
mode stopped
until_match "$control/status.json" '"state":"stopped"'
online_launches=$(grep -c 'config-online.yaml$' "$fixture/launches")
touch "$fixture/hold-validation"
mode managed-online
until_match "$fixture/validating" '^ready$'
mode managed
rm "$fixture/hold-validation"
until_match "$control/status.json" '"restarts":0.*"state":"ready"'
[[ $(grep -c 'config-online.yaml$' "$fixture/launches") == "$online_launches" ]]
mode stopped
until_match "$control/status.json" '"state":"stopped"'
touch "$fixture/invalid-config"
mode managed
until_match "$control/status.json" '"restarts":0.*"state":"degraded"'
rm "$fixture/invalid-config"
mode stopped
until_match "$control/status.json" '"state":"stopped"'
mode managed
until_match "$control/status.json" '"state":"ready"'
[[ $(<"$key") != "$first" ]]
kill -TERM "$(<"$fixture/engine.pid")"
until_match "$control/status.json" '"restarts":1.*"state":"ready"'
engine=$(<"$fixture/engine.pid")
trap - EXIT
stop_supervisor
[[ ! -d /proc/$engine ]]
protected="$fixture/root-file"
touch "$protected"
chmod 0644 "$protected"
rm "$capi"
ln -s "$protected" "$capi"
if /usr/local/bin/gosu crowdsec "$controller" --appliance-supervisor protect-capi; then exit 1; fi
[[ $(stat -c '%a' "$protected") == 644 ]]
rm "$capi"
touch "$capi"
if /usr/local/bin/gosu crowdsec "$controller" --appliance-supervisor protect-capi; then exit 1; fi
chown 10003:10003 "$capi"
chmod 0644 "$capi"
readonly alias="$state/credentials/credential-link"
ln "$capi" "$alias"
if /usr/local/bin/gosu crowdsec "$controller" --appliance-supervisor protect-capi; then exit 1; fi
[[ $(stat -c '%a' "$capi") == 644 ]]
rm "$alias"
chmod 0000 "$capi"
/usr/local/bin/gosu crowdsec "$controller" --appliance-supervisor protect-capi
[[ $(stat -c '%a' "$capi") == 600 ]]
printf 'PASS: native CrowdSec local/online transitions, credentials, enrollment, fallback, activation rotation and shutdown\n'
