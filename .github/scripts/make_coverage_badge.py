#!/usr/bin/env python3
"""Render a coverage badge as SVG, with no third-party service involved.

Coverage data is a map of the codebase — which files exist, which lines run.
There is no reason to hand that to Codecov or Coveralls when the badge is two
rectangles and some text. Self-contained also means no extra token to store,
and nothing that stops working when a service changes its free tier.

The label is "unit coverage", NOT "coverage". Most of what is uncovered in this
repo drives real hosts over ssh and kubectl; posture-check.py reads 0% and runs
nightly against a live cluster, gate.py reads 18% and is exercised by every
rebuild. A bare "coverage" badge would invite chasing a number that measures
lines executed by pytest, not whether the system works.

Usage:  make_coverage_badge.py <percent>  > coverage.svg
"""

from __future__ import annotations

import sys

LABEL = "unit coverage"


def colour(pct: int) -> str:
    if pct >= 80:
        return "#4c1"
    if pct >= 60:
        return "#97ca00"
    if pct >= 40:
        return "#dfb317"
    return "#fe7d37"


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    pct = int(sys.argv[1])
    value = f"{pct}%"
    # ~6.5px per char at 11px DejaVu Sans, plus padding either side.
    lw = int(len(LABEL) * 6.5) + 10
    vw = int(len(value) * 7.0) + 10
    total = lw + vw

    print(
        f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{LABEL}: {value}">
  <title>{LABEL}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#555"/>
    <rect x="{lw}" width="{vw}" height="20" fill="{colour(pct)}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{LABEL}</text>
    <text x="{lw / 2:.0f}" y="14">{LABEL}</text>
    <text x="{lw + vw / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{lw + vw / 2:.0f}" y="14">{value}</text>
  </g>
</svg>"""
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
