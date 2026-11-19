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
[ -z "${SMTP_PASSWORD+x}" ] && [ -z "${SMTP_USER+x}" ]
[ "$1" = -c ]
shift 2
case "$*" in
    'machines list -o json') printf '[{"machineId":"rentnerproxy-managed"}]\n' ;;
    'bouncers delete rentnerproxy-caddy') ;;
    'bouncers add rentnerproxy-caddy --key '*) [ "${#5}" = 64 ] ;;
    'capi register -f '*) echo fixture > "$4" ;;
    'capi status') ;;
    '-o json console status') echo '{"enrolled":true}' ;;
    'console enroll --disable all DEMO_0123456789-ab') ;;
    *) exit 11 ;;
esac
SH
cat > /usr/local/bin/crowdsec <<'SH'
#!/bin/sh
set -eu
[ "$(id -u):$(id -g)" = 10003:10003 ]
[ -z "${SMTP_PASSWORD+x}" ] && [ -z "${SMTP_USER+x}" ]
[ "$1" != -t ] || exit 0
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
mode stopped
export SMTP_USER=dummy SMTP_PASSWORD=dummy
"$controller" --appliance-supervisor crowdsec &
supervisor=$!
trap 'kill -TERM "$supervisor" 2>/dev/null || :; wait "$supervisor" || :' EXIT
until_match "$control/status.json" '"state":"stopped"'
mode managed
until_match "$control/status.json" '"state":"ready"'
readonly key="$state/bouncer/caddy-bouncer-key"
[[ $(stat -c '%u:%g:%a:%h' "$key") == 0:10001:440:1 && $(stat -c '%u:%g:%a' "$control/status.json") == 0:10001:440 ]]
first=$(<"$key")
until_match "$fixture/launches" 'config.yaml -no-capi'
mode managed-online
until_match "$control/status.json" '"community":"connected"'
until_match "$fixture/launches" 'config-online.yaml$'
capi="$state/credentials/online_api_credentials.yaml"
[[ $(stat -c '%u:%g:%a:%h' "$capi") == 10003:10003:600:1 ]]
id=0123456789abcdef0123456789abcdef
printf '%s\n%s\n' "$id" DEMO_0123456789-ab > "$fixture/request"
chown 10001:10001 "$fixture/request"
chmod 0600 "$fixture/request"
mv "$fixture/request" "$control/console-enrollment-request"
until_match "$control/console-enrollment-result.json" '"state":"pending"'
kill -TERM "$(<"$fixture/engine.pid")"
until_match "$control/status.json" '"community":"degraded".*"state":"ready"'
mode stopped
until_match "$control/status.json" '"state":"stopped"'
mode managed
until_match "$control/status.json" '"state":"ready"'
[[ $(<"$key") != "$first" ]]
kill -TERM "$(<"$fixture/engine.pid")"
until_match "$control/status.json" '"restarts":1.*"state":"ready"'
engine=$(<"$fixture/engine.pid")
kill -TERM "$supervisor"
wait "$supervisor"
trap - EXIT
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
