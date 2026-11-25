#!/usr/bin/env bash
set -Eeuo pipefail

case "${1:-}" in
    ''|--validate-only) ;;
    *) echo "::error::Unsupported release readiness mode."; exit 1 ;;
esac

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Recheck the original published event before publishing updater readiness.
bash "$script_directory/verify-release-identity.sh"
bun --no-env-file "$script_directory/verify-exact-revision-ci.ts"
bash "$script_directory/verify-release-identity.sh"
bun --no-env-file "$script_directory/verify-compatibility-policy-source.ts"
bun --no-env-file "$script_directory/generate-release-readiness.ts"
bun --no-env-file "$script_directory/generate-release-app-requirements.ts"
if [[ "${1:-}" == --validate-only ]]; then exit 0; fi
# Finish the app requirements upload first: a reader that sees readiness also finds them.
gh release upload "$RELEASE_TAG" \
    "$RUNNER_TEMP/rentnerproxy-release/rentnerproxy-app-requirements.json" \
    --clobber \
    --repo "$GITHUB_REPOSITORY" || {
    echo "::error::Publishing the release app requirements asset failed."
    exit 1
}
gh release upload "$RELEASE_TAG" \
    "$RUNNER_TEMP/rentnerproxy-release/rentnerproxy-update.json" \
    --clobber \
    --repo "$GITHUB_REPOSITORY" || {
    echo "::error::Publishing the release readiness asset failed."
    exit 1
}
