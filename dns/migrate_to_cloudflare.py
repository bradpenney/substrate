#!/bin/sh
"exec" "$(cd $(dirname $0)/..; pwd)/.venv/bin/python3" "-u" "$0" "$@"
"""
Replicate the zone from Vercel into Cloudflare (see ADR-037).

DRY RUN BY DEFAULT. Nothing is written without --apply.

WHY A SCRIPT AND NOT CLICKING
Cloudflare's onboarding scan imports what it can discover, and misses what it
cannot — some TXT, anything unusual. The authoritative list comes from Vercel's
API, so the replication should come from the same place. Clicking introduces a
transcription step between the two.

TWO TRANSLATIONS THAT ARE NOT RENAMES:

1. ALIAS -> CNAME. Vercel's `ALIAS` (apex flattening) has no Cloudflare
   equivalent by that name; Cloudflare flattens a CNAME at the apex natively.
   Same effect, different type. Getting this wrong takes down the apex.

2. Proxy status is OFF for everything. Orange-clouding a Vercel-served record
   stacks two CDNs and requires SSL mode Full (Strict) or it redirect-loops.
   The homelab A record must stay grey too: proxying changes the traffic path
   and breaks direct ingress.

CAA RECORDS ARE LOAD-BEARING. They restrict which CAs may issue for the domain.
`letsencrypt.org` is allowlisted here — dropping or mangling these breaks
cert-manager issuance, which is the reason for this migration.
"""

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent

# Domain and Vercel team come from the GITIGNORED site.yml, never from this
# file. The repo is public; it carries no domain, account, or host identifiers.
sys.path.insert(0, str(REPO))
import siteconfig  # noqa: E402

_DNS = siteconfig.load_model().dns
# Names allowed to be orange-clouded. Empty by default: proxy-off is the rule,
# and every exception is written down rather than discovered later.
PROXY_OK = {n.rstrip(".").lower() for n in _DNS.proxied}
DOMAIN = _DNS.domain or ""
TEAM = _DNS.vercel_team or ""
if not DOMAIN:
    sys.exit("site.yml has no dns.domain — see ADR-037")


def load_env() -> dict:
    """Parse, never source — a sourced file executes any non-KEY=VALUE line.
    That already happened once: pasted example text ran a live curl."""
    env = {}
    for line in (REPO / ".dns-migration.env").read_text().splitlines():
        m = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line.strip())
        if m:
            env[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return env


def api(url, headers, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    if data:
        headers = {**headers, "Content-Type": "application/json"}
    req = urllib.request.Request(url, headers=headers, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except Exception:
            return {"success": False, "errors": [{"message": f"HTTP {e.code}"}]}
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}


def vercel_records(env) -> list:
    h = {"Authorization": f"Bearer {env['VERCEL_TOKEN']}"}
    d = api(f"https://api.vercel.com/v4/domains/{DOMAIN}/records"
            f"?teamId={TEAM}&limit=100", h)
    return d.get("records") or []


def translate(rec) -> dict | None:
    """Vercel record -> Cloudflare record. Returns None for types Cloudflare
    manages itself (NS at apex, SOA)."""
    name = rec.get("name") or "@"
    rtype = rec.get("type")
    value = rec.get("value", "")
    ttl = int(rec.get("ttl") or 60)

    fqdn = DOMAIN if name == "@" else f"{name}.{DOMAIN}"

    if rtype in ("NS", "SOA"):
        return None  # Cloudflare owns these once the zone is authoritative

    if rtype == "ALIAS":
        # Not a rename: Cloudflare flattens a CNAME at the apex natively.
        return {"type": "CNAME", "name": fqdn, "content": value.rstrip("."),
                "ttl": ttl, "proxied": False,
                "comment": "was ALIAS on Vercel (apex/wildcard flattening)"}

    if rtype == "CAA":
        # "0 issue \"letsencrypt.org\"" -> structured fields.
        m = re.match(r'(\d+)\s+(\w+)\s+"(.*)"', value.strip())
        if not m:
            return {"_unparsed": True, "type": "CAA", "name": fqdn, "raw": value}
        flags, tag, ca = m.groups()
        return {"type": "CAA", "name": fqdn, "ttl": ttl,
                "data": {"flags": int(flags), "tag": tag, "value": ca}}

    return {"type": rtype, "name": fqdn, "content": value, "ttl": ttl,
            "proxied": False}



def cf_zone_id(cfh):
    r = api(f"https://api.cloudflare.com/client/v4/zones?name={DOMAIN}", cfh)
    res = r.get("result") or []
    return res[0]["id"] if res else None


def cf_records(cfh, zone_id) -> list:
    out, page = [], 1
    while True:
        r = api(f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
                f"/dns_records?per_page=100&page={page}", cfh)
        batch = r.get("result") or []
        out.extend(batch)
        info = r.get("result_info") or {}
        if page >= (info.get("total_pages") or 1) or not batch:
            return out
        page += 1


def key(rec) -> tuple:
    """Identity of a record for diffing: type + name + value.

    CAA is compared on its rendered form so a Vercel string and a Cloudflare
    structured record collapse to the same key. Trailing dots are stripped
    throughout — Vercel writes `foo.example.com.`, Cloudflare returns
    `foo.example.com`, and they mean the same thing.
    """
    t = rec["type"]
    name = rec["name"].rstrip(".").lower()
    if t == "CAA":
        d = rec.get("data") or {}
        val = f'{d.get("flags")} {d.get("tag")} {d.get("value")}'
    else:
        val = (rec.get("content") or "").rstrip(".").lower()
        if t == "TXT":
            # Cloudflare returns TXT content wrapped in the quotes that are part
            # of the wire format; Vercel returns the bare string. Same record,
            # two spellings — without this, every TXT shows as both missing AND
            # extra, and --prune would delete a live verification record and
            # recreate it for no reason.
            val = val.strip('"')
    return (t, name, val)


def verify(env, cfh, quiet=False) -> int:
    """Three-way diff: what Vercel says, what Cloudflare has, what differs.

    This is the step that makes the migration safe to trust. Cloudflare's
    onboarding scan imports what it can DISCOVER, which is not the same as what
    EXISTS — it cannot enumerate a zone it is not authoritative for, so it
    guesses from common names. Anything it missed is a record that silently
    stops resolving the moment the nameservers change.
    """
    zone_id = cf_zone_id(cfh)
    if not zone_id:
        print(f"no Cloudflare zone for {DOMAIN} yet — nothing to verify")
        return 1

    want = {}
    for r in vercel_records(env):
        o = translate(r)
        if o and not o.get("_unparsed"):
            want[key(o)] = o

    have = {}
    for r in cf_records(cfh, zone_id):
        if r["type"] in ("NS", "SOA"):
            continue           # Cloudflare's own, never ours to manage
        have[key(r)] = r

    missing = sorted(want.keys() - have.keys())
    extra = sorted(have.keys() - want.keys())
    match = want.keys() & have.keys()

    # Proxy status is not part of the identity key, so it is checked separately
    # — a record can match on (type, name, value) and still be orange-clouded.
    proxied = [r for r in have.values() if r.get("proxied")
               and r["name"].rstrip(".").lower() not in PROXY_OK]

    if quiet:
        return 0 if not (missing or extra or proxied) else 1

    print(f"=== diff: Vercel (source of truth) vs Cloudflare ===\n")
    print(f"  matching : {len(match)}")
    print(f"  missing  : {len(missing)}   (in Vercel, NOT in Cloudflare)")
    print(f"  extra    : {len(extra)}   (in Cloudflare, not in Vercel)")

    if missing:
        print("\n  MISSING — these would stop resolving after the cutover:")
        for t, n, v in missing:
            print(f"    {t:<6} {n:<34} {v}")
    if extra:
        print("\n  EXTRA — review each; scan artefacts and stale guesses live here:")
        for t, n, v in extra:
            print(f"    {t:<6} {n:<34} {v}")

    if proxied:
        print("\n  *** PROXIED (orange cloud) — must be OFF for this migration:")
        for r in proxied:
            print(f"    {r['type']:<6} {r['name']}")
        print("    Proxying stacks a second CDN in front of Vercel and changes")
        print("    the traffic path to the homelab. Turn these grey.")

    ok = not missing and not extra and not proxied
    print("\n  " + ("CLEAN — safe to change nameservers at Hostinger."
                     if ok else "NOT CLEAN — do not change nameservers yet."))
    return 0 if ok else 1



def _dig(name, rtype, server=None) -> list:
    """Ask a real resolver. The provider APIs describe intent; DNS gives the
    answer. Those are not the same thing, which is the whole reason this
    function exists."""
    import shutil
    import subprocess
    if not shutil.which("dig"):
        return []
    cmd = ["dig", "+short", "+time=3", "+tries=2"]
    if server:
        cmd.append("@" + server)
    cmd += [name, rtype]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return [l for l in out.stdout.splitlines() if l.strip()]
    except Exception:
        return []



def parent_delegation(domain) -> tuple:
    """The NS records the PARENT zone hands out — uncached, authoritative.

    Delegation lives in the parent, not in the zone. Asking a recursive resolver
    `dig <domain> NS` returns the NS RRset from inside the zone itself, served
    from cache, which answers a different question and cannot distinguish
    "the registrar has not pushed yet" from "my resolver still has the old
    answer". Only the TLD servers know whether the delegation actually moved.

    The referral arrives in the AUTHORITY section, not ANSWER, so `dig +short`
    prints nothing — which reads as failure and is why this is not a one-liner.

    Returns (nameservers, source_tld_server).
    """
    import shutil
    import subprocess
    if not shutil.which("dig"):
        return ([], None)
    tld = domain.rsplit(".", 1)[-1]
    try:
        out = subprocess.run(["dig", "+short", "+time=3", tld, "NS", "@1.1.1.1"],
                             capture_output=True, text=True, timeout=15)
        servers = [l.rstrip(".") for l in out.stdout.split() if l.strip()][:4]
    except Exception:
        return ([], None)

    for srv in servers:
        try:
            r = subprocess.run(
                ["dig", "+norecurse", "+time=3", "+tries=1", "@" + srv, domain, "NS"],
                capture_output=True, text=True, timeout=15)
        except Exception:
            continue
        ns, in_auth = [], False
        for line in r.stdout.splitlines():
            if "AUTHORITY SECTION" in line:
                in_auth = True
                continue
            if in_auth:
                if not line.strip():
                    break
                f = line.split()
                if len(f) >= 5 and f[3] == "NS":
                    ns.append(f[4].rstrip(".").lower())
        if ns:
            return (sorted(set(ns)), srv)
    return ([], None)



# Public resolvers polled to decide whether DNSSEC is safe to switch on. Not
# exhaustive — no such list exists — but broad enough that unanimous agreement
# means the old delegation has aged out essentially everywhere.
RESOLVERS = {
    "1.1.1.1": "Cloudflare",
    "8.8.8.8": "Google",
    "9.9.9.9": "Quad9",
    "208.67.222.222": "OpenDNS",
    "94.140.14.14": "AdGuard",
}


def resolver_convergence(target) -> tuple:
    """Which public resolvers have picked up the new delegation.

    This gates DNSSEC, and the reason is not obvious. Signing is safe once the
    PARENT delegates to the new nameservers — but a resolver that still has the
    OLD nameservers cached will:

        fetch DS from the parent      -> "this zone is signed"
        query the OLD nameservers     -> unsigned answers, no RRSIG
        -> SERVFAIL

    The domain does not look slow to those users. It looks DOWN. So the DS
    record must not be published until the old delegation has expired from
    caches, not merely from the parent zone.

    Returns (moved, stale) as lists of (ip, name).
    """
    moved, stale = [], []
    tset = {t.rstrip(".").lower() for t in target}
    for ip, name in RESOLVERS.items():
        got = {x.rstrip(".").lower() for x in _dig(DOMAIN, "NS", ip)}
        if got and got == tset:
            moved.append((ip, name))
        elif got:
            stale.append((ip, name))
    return moved, stale


def preflight(env, cfh) -> int:
    """Everything that must be true BEFORE the nameservers change.

    The cutover is reversible in about 60s — every TTL here is already 60 — with
    exactly one exception, and it is total. See ADR-039.
    """
    print("=== pre-flight: safe to change nameservers? ===\n")
    blocking = []

    # 1. DNSSEC. The one unrecoverable failure mode.
    #
    # If the parent zone publishes a DS record for the OLD nameservers' keys and
    # the delegation moves, every validating resolver rejects the new answers as
    # forged. The domain does not degrade — it vanishes, globally, including for
    # whoever is trying to fix it, and it cannot be rolled back faster than the
    # PARENT zone's TTL, which is not 60 seconds.
    ds = []
    for r in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        ds += _dig(DOMAIN, "DS", r)
    if ds:
        blocking.append(
            "DNSSEC is ACTIVE (a DS record exists in the parent zone).\n"
            "      Remove the DS record at the registrar and wait for it to\n"
            "      expire from the parent BEFORE changing nameservers. Moving\n"
            "      with a stale DS takes the domain down globally. (ADR-039)")
        print("  [!!] DNSSEC:   DS record present — " + "; ".join(sorted(set(ds))))
    else:
        print("  [ok] DNSSEC:   unsigned, no DS in parent — safe to move")

    # 2. The record diff must be clean.
    print("  ...  diff:     checking", flush=True)
    clean = verify(env, cfh, quiet=True)
    if clean == 0:
        print("  [ok] diff:     Cloudflare matches Vercel exactly")
    else:
        blocking.append("record diff is NOT clean — run --verify to see it")
        print("  [!!] diff:     mismatch — run --verify")

    # 3. Delegation, read from the PARENT zone rather than a recursive resolver.
    current, via = parent_delegation(DOMAIN)
    cached = sorted(x.rstrip(".").lower() for x in _dig(DOMAIN, "NS"))
    zone_id = cf_zone_id(cfh)
    z = api(f"https://api.cloudflare.com/client/v4/zones/{zone_id}", cfh) if zone_id else {}
    zres = z.get("result") or {}
    target = sorted(x.rstrip(".").lower() for x in (zres.get("name_servers") or []))
    status = zres.get("status")

    print(f"  [--] status:   Cloudflare zone is '{status}'"
          + ("  (expected until delegation)" if status != "active" else ""))
    print(f"  [--] parent:   {', '.join(current) or '?'}"
          + (f"   (per {via}, uncached)" if via else ""))
    if cached and cached != current:
        print(f"  [--] resolvers:{', '.join(cached)}   (cached; parent is truth)")
    print(f"  [--] target:   {', '.join(target) or '?'}")

    done = bool(current) and current == target
    if done:
        print("\n  DELEGATION HAS MOVED — the parent zone points at Cloudflare.")
    elif current:
        print("\n  Delegation has NOT moved yet. The parent registry still hands"
              "\n  out the old nameservers, so the registrar has not pushed the"
              "\n  change. This is uncached — waiting longer is the only fix.")

    print()
    if done and status == "active":
        print("  CUTOVER COMPLETE.\n")
        moved, stale = resolver_convergence(target)
        print("  Resolver convergence (gates DNSSEC):")
        for ip, nm in moved:
            print(f"    [new] {nm:<11} {ip}")
        for ip, nm in stale:
            print(f"    [OLD] {nm:<11} {ip}   <- still cached")

        if stale:
            print(f"\n  DNSSEC: NOT YET. {len(stale)} resolver(s) still cache the old")
            print("  delegation. Publishing a DS record now would SERVFAIL for their")
            print("  users — the parent would say 'signed' while those resolvers ask")
            print("  the OLD, unsigned nameservers. That reads as DOWN, not slow.")
            print("  Re-run --preflight until every resolver reads [new].")
            return 0

        print("\n  DNSSEC: SAFE TO ENABLE — every resolver polled has moved.")
        print("    1. Cloudflare -> DNS -> Settings -> Enable DNSSEC")
        print("    2. copy the DS record it generates")
        print("    3. add that DS record at the registrar")
        print("  Order matters: a DS record pointing at keys nobody is signing")
        print("  with fails validation exactly as badly as a stale one.")
        return 0
    if done:
        print(f"  Delegation moved; Cloudflare zone still '{status}'. It flips to")
        print("  'active' on its own within ~an hour. Re-run then.")
        return 0

    if blocking:
        print("  BLOCKED — do not change nameservers:")
        for b in blocking:
            print(f"    - {b}")
        return 1

    print("  CLEAR TO CUT OVER. At the registrar, replace the nameservers with:")
    for t in target:
        print(f"      {t}")
    print("\n  Then, IN THIS ORDER (ADR-039):")
    print("    1. wait for the Cloudflare zone to report 'active'")
    print("    2. re-run --preflight to confirm the delegation moved")
    print("    3. ONLY THEN enable DNSSEC + add the DS record at the registrar")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="actually create the zone and records (default: dry run)")
    ap.add_argument("--prune", action="store_true",
                    help="with --apply, delete Cloudflare records absent from Vercel")
    ap.add_argument("--preflight", action="store_true",
                    help="all checks that must pass BEFORE changing nameservers")
    ap.add_argument("--verify", action="store_true",
                    help="diff Cloudflare against Vercel and exit (read-only)")
    args = ap.parse_args()

    env = load_env()
    cfh = {"Authorization": f"Bearer {env['CLOUDFLARE_TOKEN']}"}

    if args.preflight:
        return preflight(env, cfh)
    if args.verify:
        return verify(env, cfh)

    src = vercel_records(env)
    if not src:
        print("could not read Vercel records", file=sys.stderr)
        return 1
    print(f"=== {len(src)} records from Vercel ===\n")

    planned, skipped, problems = [], [], []
    for r in src:
        out = translate(r)
        if out is None:
            skipped.append(r)
        elif out.get("_unparsed"):
            problems.append(out)
        else:
            planned.append((r, out))

    print(f"  {'VERCEL':<28} ->  CLOUDFLARE")
    print("  " + "-" * 86)
    for r, o in sorted(planned, key=lambda x: (x[1]["type"], x[1]["name"])):
        src_desc = f"{(r.get('name') or '@'):<14} {r.get('type'):<6}"
        if o["type"] == "CAA":
            dst = f"CAA   {o['data']['flags']} {o['data']['tag']} {o['data']['value']}"
        else:
            dst = f"{o['type']:<6}{o['content'][:44]}"
        note = "  [ALIAS->CNAME]" if "was ALIAS" in (o.get("comment") or "") else ""
        print(f"  {src_desc} ->  {dst}{note}")

    if skipped:
        print(f"\n  skipped (Cloudflare manages these): "
              f"{', '.join(s.get('type') for s in skipped)}")
    if problems:
        print("\n  *** COULD NOT TRANSLATE ***")
        for p in problems:
            print(f"    {p['name']} {p['type']}: {p['raw']}")
        print("  Refusing to proceed with unparsed records.")
        return 1

    print(f"\n  total to create: {len(planned)}   proxied: 0 (all DNS-only)")

    if not args.apply:
        print("\nDRY RUN — nothing written. Re-run with --apply to create.")
        return 0

    # ---- find or create the zone ----
    zone_id = cf_zone_id(cfh)
    if zone_id:
        print(f"\n  zone exists: {zone_id}")
    else:
        body = {"name": DOMAIN, "type": "full"}
        if env.get("CLOUDFLARE_ACCOUNT_ID"):
            body["account"] = {"id": env["CLOUDFLARE_ACCOUNT_ID"]}
        z = api("https://api.cloudflare.com/client/v4/zones", cfh, "POST", body)
        if not z.get("success"):
            print("  zone creation failed:",
                  [e.get("message") for e in z.get("errors") or []], file=sys.stderr)
            print("  (the token likely lacks account-level Zone:Edit — create the"
                  " zone in the dashboard instead)", file=sys.stderr)
            return 1
        zone_id = z["result"]["id"]
        print(f"\n  zone created: {zone_id}")

    ns = api(f"https://api.cloudflare.com/client/v4/zones/{zone_id}", cfh)
    ns_list = ((ns.get("result") or {}).get("name_servers")) or []
    if ns_list:
        print(f"  assigned nameservers: {', '.join(ns_list)}")

    # ---- reconcile against what is already there ----
    want = {key(o): o for _, o in planned}
    have = {}
    for r in cf_records(cfh, zone_id):
        if r["type"] in ("NS", "SOA"):
            continue
        have[key(r)] = r

    base = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    failed = 0

    # ORDER MATTERS: prune BEFORE create.
    #
    # DNS forbids a CNAME coexisting with any other record at the same name, and
    # Cloudflare enforces it. The scan resolved Vercel's ALIAS records into
    # hardcoded A records at the apex and the wildcard, so creating the correct
    # CNAMEs first fails on exactly the two records that matter most.
    #
    # Deleting before creating normally leaves a resolution gap. Not here: this
    # zone is not authoritative yet — nothing on the internet is asking it
    # anything until the nameservers change at the registrar.

    # 1. remove what the scan invented
    extra = [r for k, r in have.items() if k not in want]
    if extra and not args.prune:
        print(f"\n  {len(extra)} EXTRA record(s) in Cloudflare but not in Vercel."
              f"\n  Re-run with --prune to remove them. Records that conflict"
              f"\n  (A at a name that needs a CNAME) cannot be created until then:")
        for r in extra:
            print(f"    {r['type']:<6} {r['name']:<34} {r.get('content','')}")
    elif extra:
        print(f"\n  pruning {len(extra)} scan artefact(s):")
        for r in extra:
            d = api(f"{base}/{r['id']}", cfh, "DELETE")
            ok = d.get("success") or (d.get("result") or {}).get("id")
            print(f"    {'del ' if ok else 'FAIL'} {r['type']:<6} {r['name']:<32}"
                  f" {r.get('content','')}")
            if not ok:
                failed += 1

    # 2. create what Vercel has and Cloudflare does not
    todo = [o for k, o in want.items() if k not in have]
    print(f"\n  creating {len(todo)} missing record(s):")
    for o in todo:
        payload = {k: v for k, v in o.items() if not k.startswith("_")}
        r = api(base, cfh, "POST", payload)
        if r.get("success"):
            print(f"    ok   {o['type']:<6} {o['name']:<32} {o.get('content','')}")
        else:
            msgs = [e.get("message") for e in r.get("errors") or []]
            if any("already exists" in (m or "") for m in msgs):
                print(f"    dup  {o['type']:<6} {o['name']}")
            else:
                failed += 1
                print(f"    FAIL {o['type']:<6} {o['name']}: {msgs}")
    if not todo:
        print("    (none)")

    # 3. un-proxy everything, LAST — records created above land proxied too.
    #
    # Cloudflare orange-clouds A/CNAME by default. Wrong on both paths here: in
    # front of Vercel it stacks a second CDN and needs SSL mode Full (Strict) or
    # it redirect-loops; in front of the homelab it changes the traffic path and
    # breaks direct ingress. Proxying is a deliberate per-record decision AFTER
    # the cutover, not a default inherited from an import.
    proxied = [r for r in cf_records(cfh, zone_id) if r.get("proxied")
               and r["name"].rstrip(".").lower() not in PROXY_OK]
    print(f"\n  un-proxying {len(proxied)} record(s):")
    for r in proxied:
        u = api(f"{base}/{r['id']}", cfh, "PATCH", {"proxied": False})
        if u.get("success"):
            print(f"    grey {r['type']:<6} {r['name']}")
        else:
            failed += 1
            print(f"    FAIL {r['type']:<6} {r['name']}: "
                  f"{[e.get('message') for e in u.get('errors') or []]}")
    if not proxied:
        print("    (none)")

    print(f"\n  {'DONE' if not failed else str(failed) + ' FAILED'}")
    print("  Re-run with --verify to confirm the diff is clean before touching"
          " nameservers.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
