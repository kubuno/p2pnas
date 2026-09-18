#!/usr/bin/env bash
# Attach a built artifact to the GitHub Release for the current tag.
#
# This job does NOT depend on another workflow having created the release first.
# It used to: it waited ten minutes for build.yml (which ships the .deb) and then
# gave up with "release never appeared — build.yml likely failed". That message
# was wrong and the failure was avoidable — on a repository whose .deb takes
# longer than ten minutes to build, the release simply had not been created yet,
# and a perfectly good package was thrown away. Four modules reached v0.1.6 with
# missing packages that way.
#
# Instead, the release is created here when it is missing. Several jobs may reach
# that point at once, so losing the race is expected and harmless: whoever loses
# finds the release already there and uploads to it.
set -euo pipefail

glob="$1"                       # e.g. 'dist/*.rpm'
tag="${GITHUB_REF_NAME}"
repo="${GITHUB_REPOSITORY}"

ensure_release() {
  if gh release view "$tag" -R "$repo" >/dev/null 2>&1; then
    return 0
  fi
  echo "release $tag missing — creating it"
  # --verify-tag: never invent a release for a tag that does not exist.
  # A concurrent job may win this race; that is not an error.
  if gh release create "$tag" -R "$repo" --verify-tag --title "$tag" --generate-notes >/dev/null 2>&1; then
    return 0
  fi
  sleep 5
  gh release view "$tag" -R "$repo" >/dev/null 2>&1
}

for i in $(seq 1 5); do
  if ensure_release; then
    break
  fi
  echo "release $tag not available yet ($i/5)…"
  sleep 10
done

if ! gh release view "$tag" -R "$repo" >/dev/null 2>&1; then
  echo "::error::release $tag could not be created or found" >&2
  exit 1
fi

# shellcheck disable=SC2086 — intentional glob expansion
gh release upload "$tag" $glob --clobber -R "$repo"
