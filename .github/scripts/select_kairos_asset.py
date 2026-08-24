#!/usr/bin/env python3
"""
Pick the right Kairos ISO from a release, and refuse unsafe choices.

WHY THIS IS A SCRIPT AND NOT INLINE IN THE WORKFLOW
The first version embedded this logic as Python inside a shell pipeline inside
YAML — three escaping layers — and broke the workflow file. That is the same
trap recorded in ADR-032 (YAML folding vs shell continuations): the bug lives
in the boundary, not in any single layer. Logic that needs quoting belongs in a
file, where it can also be tested.

WHAT IT GUARDS AGAINST
Kairos publishes a BUILD MATRIX — one image per bundled k0s version. Release
v4.2.0 shipped k0s 1.34.10, 1.35.7 and 1.36.3 simultaneously. Two distinct
mistakes are possible:

  1. Taking the FIRST match. That picked 1.34.10 against a cluster running
     1.36.1 — a two-minor Kubernetes DOWNGRADE, purely from asset ordering.
  2. Taking the highest blindly. A future release could offer a k0s two minor
     versions ahead, which exceeds the supported upgrade skew.

So: select the HIGHEST k0s available, then verify the jump is sane.

Usage:
    select_kairos_asset.py --current-url <current iso_url> < release.json
Prints the chosen URL on stdout. Exits non-zero, with an explanation on stderr,
if no safe choice exists.
"""

import argparse
import json
import re
import sys
import urllib.parse

FLAVOUR = ("kairos-hadron-", "standard-amd64-generic")


def k0s_version(url: str):
    """The bundled k0s version, or None. URL-decodes first — the `+` in
    `k0sv1.36.3+k0s.2` arrives from the API as `%2B`."""
    m = re.search(r"k0sv([\d.]+)\+k0s", urllib.parse.unquote(url))
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--current-url", required=True)
    args = ap.parse_args()

    # strict=False: GitHub release bodies contain raw control characters that
    # Python's strict JSON parser rejects (jq tolerates them).
    release = json.loads(sys.stdin.read(), strict=False)

    current = k0s_version(args.current_url)
    if current is None:
        print("could not parse the CURRENT k0s version — refusing to guess", file=sys.stderr)
        return 1

    candidates = []
    for asset in release.get("assets", []):
        url = asset["browser_download_url"]
        if not url.endswith(".iso"):
            continue
        # Flavour is held constant. Switching it is an architectural change,
        # not a version bump.
        if not all(f in url for f in FLAVOUR):
            continue
        version = k0s_version(url)
        if version:
            candidates.append((version, url))

    if not candidates:
        print("no matching hadron/standard/amd64/generic k0s ISO in this release", file=sys.stderr)
        return 1

    version, url = max(candidates)
    cur_s, new_s = ".".join(map(str, current)), ".".join(map(str, version))

    if version < current:
        print(f"REFUSING: best available k0s is {new_s}, older than the running {cur_s}. "
              f"Kubernetes has no supported downgrade path.", file=sys.stderr)
        return 1

    if version[:2] == current[:2]:
        print(f"patch upgrade: k0s {cur_s} -> {new_s}", file=sys.stderr)
    elif version[1] - current[1] == 1:
        print(f"MINOR upgrade: k0s {cur_s} -> {new_s} — review release notes", file=sys.stderr)
    elif version[1] > current[1] + 1:
        print(f"REFUSING: k0s {cur_s} -> {new_s} skips a minor version. "
              f"Kubernetes supports at most +1 minor per upgrade; roll through "
              f"the intermediate release first.", file=sys.stderr)
        return 1

    print(url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
