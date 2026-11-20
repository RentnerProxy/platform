#!/usr/bin/env bash
set -euo pipefail

output=${1:?Expected an evidence output directory}
repository_id=${2:?Expected a source repository ID}
revision=$(git rev-parse HEAD)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$output" "$work/packages"
rm -f -- "$output/greeting.json" "$output/greeting-browser.json"

template=web/src/tests/fixtures/app-template
for target in linux-amd64 linux-arm64; do
    bun --no-env-file "$template/build.ts" package "$work/packages/$target" "$repository_id" "$revision" "$target"
done

case "$(uname -m)" in
    x86_64) native=linux-amd64 ;;
    aarch64) native=linux-arm64 ;;
    *) exit 1 ;;
esac
bun --no-env-file web/src/tests/fixtures/app-runtime-reference/greeting-browser.mts \
    "$work/packages/$native/ui" "$output/greeting-browser.json"

artifacts=$(cargo test --locked --manifest-path core/Cargo.toml --lib --no-run --message-format=json)
app_tests=$(jq -er 'select(.reason == "compiler-artifact" and .target.kind == ["lib"] and .profile.test) | .executable // empty' <<< "$artifacts")
test -x "$app_tests"

# The shared installer checks the linked ELF interpreter and versioned symbols
# against the appliance's Debian 13 library layout. The fixture serves no TCP.
docker run --rm --network none --read-only --user 0:0 \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add KILL --cap-add SETGID --cap-add SETUID \
    --security-opt no-new-privileges \
    --tmpfs '/run:rw,exec,mode=0755,size=1024m' \
    --mount "type=bind,source=$app_tests,target=/app-tests,readonly" \
    --mount "type=bind,source=$work/packages,target=/packages,readonly" \
    --env RENTNERPROXY_TEST_GREETING_PACKAGES=/packages \
    mirror.gcr.io/library/rust:1.100-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31 \
    /app-tests --ignored --exact app_install::tests::greeting::privileged_signed_greeting_package --nocapture \
    | tee "$work/result.log"

sed -n 's/^GREETING_EVIDENCE //p' "$work/result.log" > "$output/greeting.json"
test -s "$output/greeting.json"
jq -e --arg revision "$revision" '.revision == $revision and (.checks | length == 5)' "$output/greeting.json" >/dev/null
jq -se '.[0].uiBundleSha256 == .[1].uiBundleSha256' "$output/greeting.json" "$output/greeting-browser.json" >/dev/null
