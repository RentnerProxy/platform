#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --privileged-app-ipc ]]; then
    target_directory=$(cargo metadata --manifest-path core/Cargo.toml --no-deps --format-version 1 | jq -er .target_directory)
    # show-env does not append cargo llvm-cov test's target subdirectory.
    export CARGO_TARGET_DIR="$target_directory/llvm-cov-target"
    coverage_environment=$(cargo llvm-cov show-env --manifest-path core/Cargo.toml --sh)
    eval "$coverage_environment"
    artifacts=$(cargo test --locked --manifest-path core/Cargo.toml --all-features --no-run --message-format=json)
    ipc_tests=$(jq -r 'select(.reason == "compiler-artifact" and .target.kind == ["lib"] and .profile.test) | .executable // empty' <<< "$artifacts")
    controller=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "rentnerproxy-controller" and .target.kind == ["bin"] and (.profile.test | not)) | .executable // empty' <<< "$artifacts")
    test -x "$ipc_tests"
    test -x "$controller"
    profiles=$(mktemp -d)
    trap 'rm -rf -- "$profiles"' EXIT
    mkdir -m 1777 "$profiles/data"
    # Keep coverage sections while keeping the executables copied into /run small.
    objcopy --strip-debug "$ipc_tests" "$profiles/ipc-tests"
    objcopy --strip-debug "$controller" "$profiles/controller"
    rustc --edition=2024 -C opt-level=s -C strip=symbols \
        core/tests/fixtures/app-manager/app.rs -o "$profiles/fixture-app"
    rustc --edition=2024 -C opt-level=s -C strip=symbols \
        core/tests/fixtures/appliance-supervisor/crowdsec.rs -o "$profiles/crowdsec-fixture"

    # Run only the app IPC fixtures that need real UID changes. The container
    # receives test executables and a profile directory, with no network or source tree.
    runner=(
        docker run --rm --network none --read-only --user 0:0
        --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add KILL --cap-add SETGID --cap-add SETUID \
        --security-opt no-new-privileges \
        --tmpfs '/run:rw,exec,mode=0755,size=512m' \
        --mount "type=bind,source=$profiles/ipc-tests,target=/ipc-tests,readonly" \
        --mount "type=bind,source=$profiles/controller,target=/controller,readonly" \
        --mount "type=bind,source=$profiles/data,target=/profiles" \
        --env LLVM_PROFILE_FILE=/profiles/app-ipc-%p-%m.profraw \
        --env RENTNERPROXY_TEST_CONTROLLER=/controller
    )
    "${runner[@]}" \
        mirror.gcr.io/library/ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8 \
        /ipc-tests --test-threads=1 --ignored app_ipc::tests::privileged_
    # The application verifier cross-checks ELF linkage with the image's readelf.
    native_fixture_image=mirror.gcr.io/library/rust:1.100-trixie@sha256:e19840879045c951c905d0eaa9887f3439c62000e429963371b376bac8d38c31
    "${runner[@]}" \
        --tmpfs /root:rw,mode=0700,size=64m \
        "$native_fixture_image" \
        /ipc-tests --test-threads=1 app_manager::tests:: app_install::tests:: app_backup::tests::
    "${runner[@]}" \
        --tmpfs /var/lib/rentnerproxy:rw,exec,mode=0755,size=128m \
        --tmpfs /tmp:rw,mode=01777,size=128m \
        --mount "type=bind,source=$profiles/fixture-app,target=/fixture-app,readonly" \
        --env RENTNERPROXY_TEST_APP=/fixture-app \
        "$native_fixture_image" \
        /ipc-tests --ignored --exact app_manager::tests::privileged_signed_lifecycle
    "${runner[@]}" \
        --tmpfs /var/lib/rentnerproxy:rw,mode=0755,size=64m \
        --tmpfs /tmp:rw,mode=01777,size=64m \
        --tmpfs /usr/local/bin:rw,exec,mode=0755,size=8m \
        --mount "type=bind,source=$profiles/controller,target=/usr/local/bin/rentnerproxy-controller,readonly" \
        --mount "type=bind,source=$profiles/crowdsec-fixture,target=/crowdsec-fixture,readonly" \
        --mount "type=bind,source=$PWD/docker/production,target=/production,readonly" \
        "$native_fixture_image" \
        bash -eu -c 'bash /production/tests/crowdsec-supervisor.sh
            bash /production/tests/fault-supervisor.sh
            bash /production/tests/backups.sh --linux-processes'
    "${runner[@]}" \
        --tmpfs /var/lib/rentnerproxy:rw,mode=0755,size=64m \
        --tmpfs /tmp:rw,mode=01777,size=128m \
        --mount "type=bind,source=$PWD/docker/production/tests/app-provision.sh,target=/app-provision.sh,readonly" \
        --entrypoint /bin/bash \
        mirror.gcr.io/library/postgres:18.7@sha256:e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61 \
        /app-provision.sh
    cp -- "$profiles/data"/*.profraw "$(dirname "$LLVM_PROFILE_FILE")/"
    exit
fi

report_directory=core/target/coverage
mkdir -p "$report_directory"
rm -f "$report_directory/groups.json" "$report_directory/summary.json"

cargo llvm-cov report --manifest-path core/Cargo.toml --html --output-dir "$report_directory"
cargo llvm-cov report --manifest-path core/Cargo.toml --lcov --output-path "$report_directory/lcov.info"
cargo llvm-cov report --manifest-path core/Cargo.toml --json --summary-only --output-path "$report_directory/summary.json"

jq '
    def metric: {covered: .covered, total: .count, percent: (if .count == 0 then null else .covered * 100 / .count end)};
    def metrics: {lines: (.lines | metric), functions: (.functions | metric), regions: (.regions | metric)};
    .data[0] as $coverage |
    [
      {name: "Rust certificates", pattern: "core/src/runtime/(certificates|renewal)"},
      {name: "Rust ACME", pattern: "core/src/runtime/acme"},
      {name: "Rust CrowdSec runtime", pattern: "core/src/runtime/crowdsec"},
      {name: "Rust runtime engine", pattern: "core/src/runtime/engine"},
      {name: "Rust DNS", pattern: "core/src/runtime/(dns|manual_dns_propagation)"},
      {name: "Rust management API", pattern: "core/src/server"},
      {name: "Rust proxy", pattern: "core/src/runtime/(proxy|renderer|upstream_)"},
      {name: "Rust configuration and persistence", pattern: "core/src/(config[.]rs|runtime/(state|configuration|backups))"}
    ] as $groups |
    {version: 1, minimum: 90, groups:
      ([({name: "Rust overall"} + ($coverage.totals | metrics))] +
      [$groups[] as $group |
        [$coverage.files[] | select(.filename | test($group.pattern)) | .summary] as $files |
        if ($files | length) == 0 then error("Missing Rust coverage group: " + $group.name) else
          {name: $group.name} +
          (reduce $files[] as $file ({lines: {covered: 0, count: 0}, functions: {covered: 0, count: 0}, regions: {covered: 0, count: 0}};
             .lines.covered += $file.lines.covered | .lines.count += $file.lines.count |
             .functions.covered += $file.functions.covered | .functions.count += $file.functions.count |
             .regions.covered += $file.regions.covered | .regions.count += $file.regions.count) | metrics)
        end])
    }
' "$report_directory/summary.json" > "$report_directory/groups.json"

jq -e 'all(.groups[]; all(del(.name)[]; .total > 0 and .covered * 100 >= .total * 90))' "$report_directory/groups.json" >/dev/null

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        printf '### Rust coverage (Linux)\n\n'
        printf '| Metric | Covered | Total | Coverage |\n| --- | ---: | ---: | ---: |\n'
        jq -r '.data[0].totals | to_entries[] | select(.key == "lines" or .key == "functions" or .key == "regions") | "| \(.key) | \(.value.covered) | \(.value.count) | \((.value.percent * 100 | round) / 100)% |"' "$report_directory/summary.json"
        printf '\nRequired lines, functions, and regions coverage: **90%% each**. HTML and LCOV reports are available in the **rust-coverage-linux** artifact.\n'
        jq -r '.groups[] | .name as $name | del(.name) | to_entries[] | "| \($name): \(.key) | \(.value.covered) | \(.value.total) | \((.value.percent * 100 | round) / 100)% |"' "$report_directory/groups.json"
    } >> "$GITHUB_STEP_SUMMARY"
fi

cargo llvm-cov report --manifest-path core/Cargo.toml --fail-under-lines 90 --fail-under-functions 90 --fail-under-regions 90
