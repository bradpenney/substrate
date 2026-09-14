#!/usr/bin/env bash
# Install ONE released version of substrate, verified, to /usr/local/bin.
#
# Usage:  ./install.sh v0.2.0            (from a checkout, or curl'd)
#         REPO=owner/name ./install.sh v0.2.0
#
# ADR-192: the fleet is changed only by a released artifact. This is the only
# sanctioned way a substrate binary reaches a host. It:
#   1. downloads the release asset, its sha256 and its cosign bundle,
#   2. checks the sha256,
#   3. verifies the cosign signature against the RELEASE WORKFLOW's identity
#      (not "any signature": the certificate must name this repository's
#      release.yaml, the same pin the config artifact uses),
#   4. installs the binary, then asks it what it is and refuses a mismatch.
#
# There is no "latest". A version is an argument, always.
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "not a release tag: $VERSION" >&2; exit 2;; esac

REPO="${REPO:-bradpenney/substrate}"
ASSET="substrate-x86_64-unknown-linux-musl"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yaml@refs/tags/${VERSION}"
ISSUER="https://token.actions.githubusercontent.com"
DEST="${DEST:-/usr/local/bin/substrate}"

command -v cosign >/dev/null || { echo "cosign is required to verify the release: run 'substrate deploy-updates --apply' first (it installs cosign pinned by checksum from versions.yml)" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "==> ${REPO} ${VERSION}"
for f in "$ASSET" "$ASSET.sha256" "$ASSET.sigstore.json"; do
    curl -fsSL -o "$f" "$BASE/$f"
done

echo "==> checksum"
sha256sum -c "$ASSET.sha256"

echo "==> signature (must be ${IDENTITY})"
cosign verify-blob \
    --bundle "$ASSET.sigstore.json" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$ASSET"

chmod 0755 "$ASSET"
got=$("./$ASSET" --version)
case "$got" in *"(${VERSION})"*) ;; *) echo "binary reports '$got', expected a build of ${VERSION}" >&2; exit 1;; esac

echo "==> installing to ${DEST} (sudo)"
sudo install -m 0755 -o root -g root "$ASSET" "$DEST"
echo "==> $("$DEST" --version)"
