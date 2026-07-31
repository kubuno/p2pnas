#!/usr/bin/env bash
# Attach a built artifact to the GitHub Release for the current tag.
#
# The Release is created by a single workflow (build.yml, which ships the .deb).
# Every other packaging job (rpm/windows/macos in dist.yml) only *uploads* to it,
# so no two jobs ever race to create/finalize the same release. We wait for the
# release to appear, then upload with --clobber (idempotent on re-runs).
set -euo pipefail

glob="$1"                       # e.g. 'dist/*.rpm'
tag="${GITHUB_REF_NAME}"
repo="${GITHUB_REPOSITORY}"

# Wait up to ~10 min for build.yml to create the release.
for i in $(seq 1 60); do
  if gh release view "$tag" -R "$repo" >/dev/null 2>&1; then
    break
  fi
  echo "waiting for release $tag to be created by build.yml ($i/60)…"
  sleep 10
done

if ! gh release view "$tag" -R "$repo" >/dev/null 2>&1; then
  echo "::error::release $tag never appeared — build.yml likely failed" >&2
  exit 1
fi

# shellcheck disable=SC2086 — intentional glob expansion
gh release upload "$tag" $glob --clobber -R "$repo"
