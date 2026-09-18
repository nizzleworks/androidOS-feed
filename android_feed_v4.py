#!/usr/bin/env python3
"""
Android release intelligence feed - v4.

New in v4:
  - majors[]: per-version release date, support/EOL dates, tier (N/N-1/N-2),
    and this month's CVE exposure for that branch
  - CVEs split by patch level (-01 vs -05), which is what SPL policy turns on
  - QPR branches preserved (16-qpr2 is not 16)
  - Type column captured (RCE/EoP/ID/DoS)
  - vendor/component breakdown (Qualcomm, MediaTek, Arm, ...)
  - Mainline (Google Play system update) CVEs flagged - these ship without an OTA
  - bulletin published/updated/revision tracking
  - rolling history appended from the previous android_feed.json
  - urgency replaces the always-true act_now

Run:  python3 android_feed_v4.py
Out:  android_feed.json

Deps: pip install requests beautifulsoup4
"""

import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

import requests
from bs4 import BeautifulSoup

EOL_API = "https://endoflife.date/api/android.json"
BULLETIN_INDEX = "https://source.android.com/docs/security/bulletin"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = {"User-Agent": "android-feed/0.4 (nizzleworks)"}

OUT_FILE = "android_feed.json"
HISTORY_MONTHS = 12

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
PATCH_LEVEL_RE = re.compile(r"\b(20\d{2}-\d{2}-0[15])\b")
SEVERITIES = ("Critical", "High", "Moderate", "Low")
TYPES = ("RCE", "EoP", "ID", "DoS")

MAINLINE_SECTION = "google play system updates"


# ------------------------------------------------------------------ helpers

def today():
    return date.today()


def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def is_past(value):
    """endoflife.date dates: True/False/None or an ISO date string."""
    if value in (None, False):
        return False
    if value is True:
        return True
    d = parse_date(value)
    return bool(d and d <= today())


# ----------------------------------------------------------------- versions

def build_majors():
    """One block per Android major, newest first, with lifecycle detail."""
    r = requests.get(EOL_API, headers=UA, timeout=30)
    r.raise_for_status()
    cycles = r.json()

    majors = []
    for c in cycles:
        eol = c.get("eol")
        support = c.get("support")
        released = parse_date(c.get("releaseDate"))

        majors.append({
            "version": c["cycle"],
            "release_date": c.get("releaseDate"),
            "days_since_release": (today() - released).days if released else None,
            "latest_point_release": c.get("latest"),
            "latest_point_release_date": c.get("latestReleaseDate"),
            "active_support_until": support if isinstance(support, str) else None,
            "security_support_until": eol if isinstance(eol, str) else None,
            "receiving_patches": not is_past(eol),
            "active_support": not is_past(support) if support is not None else None,
        })

    # tier is relative position among branches still getting security patches
    tiers = ["N", "N-1", "N-2"]
    supported = [m for m in majors if m["receiving_patches"]]
    for i, m in enumerate(supported):
        m["tier"] = tiers[i] if i < len(tiers) else f"N-{i}"
    for m in majors:
        m.setdefault("tier", None)

    return majors, [m["version"] for m in supported]


# ----------------------------------------------------------------- bulletin

def bulletin_months():
    try:
        r = requests.get(BULLETIN_INDEX, headers=UA, timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        found = {
            m.group(1)
            for a in soup.find_all("a", href=True)
            if (m := re.search(r"/bulletin/20\d{2}/(20\d{2}-\d{2}-01)", a["href"]))
        }
    except requests.RequestException:
        found = set()

    # always also try recent months, in case the index renders client-side
    d = today().replace(day=1)
    for _ in range(3):
        found.add(d.strftime("%Y-%m-01"))
        d = (d - timedelta(days=1)).replace(day=1)

    return sorted(found, reverse=True)


def cell_text(cell):
    return cell.get_text(" ", strip=True)


def parse_tables(soup):
    """Walk the page in document order, tracking which patch level (h2)
    and which component section (h3) each table belongs to."""
    rows = []
    current_level = None
    current_section = None

    for el in soup.find_all(["h2", "h3", "table"]):
        if el.name == "h2":
            text = cell_text(el)
            m = PATCH_LEVEL_RE.search(text)
            current_level = m.group(1) if m and "patch level" in text.lower() else None
            current_section = None
            continue

        if el.name == "h3":
            current_section = cell_text(el)
            continue

        headers = [cell_text(th).lower() for th in el.find_all("th")]
        if not headers or not any("cve" in h for h in headers):
            continue

        def col(*names):
            for i, h in enumerate(headers):
                if any(n in h for n in names):
                    return i
            return None

        i_cve = col("cve")
        i_sev = col("severity")
        i_type = col("type")
        i_ver = col("updated aosp", "aosp version")
        i_sub = col("subcomponent")

        is_mainline = (current_section or "").lower() == MAINLINE_SECTION

        for tr in el.find_all("tr"):
            cells = tr.find_all("td")
            if not cells:
                continue

            # Mainline table lists several CVEs in one cell
            if is_mainline:
                for cve in CVE_RE.findall(cell_text(tr)):
                    rows.append({"cve": cve, "mainline": True})
                continue

            if i_cve is None or i_cve >= len(cells):
                continue
            m = CVE_RE.search(cell_text(cells[i_cve]))
            if not m:
                continue

            sev = cell_text(cells[i_sev]).title() if i_sev is not None and i_sev < len(cells) else ""
            vtype = cell_text(cells[i_type]) if i_type is not None and i_type < len(cells) else ""
            branches = []
            if i_ver is not None and i_ver < len(cells):
                branches = [b.strip() for b in cell_text(cells[i_ver]).split(",") if b.strip()]
            sub = cell_text(cells[i_sub]) if i_sub is not None and i_sub < len(cells) else ""

            rows.append({
                "cve": m.group(0),
                "severity": sev if sev in SEVERITIES else "Unknown",
                "type": vtype if vtype in TYPES else "",
                "branches": branches,
                "component": current_section or "Unknown",
                "subcomponent": sub,
                "patch_level": current_level,
                "mainline": False,
            })

    return rows


def parse_revisions(soup):
    """Published / Updated dates and the Versions table at the bottom."""
    text = soup.get_text(" ", strip=True)
    out = {}

    m = re.search(r"Published\s+([A-Z][a-z]+ \d{1,2}, 20\d{2})", text)
    if m:
        out["published"] = m.group(1)
    m = re.search(r"Updated\s+([A-Z][a-z]+ \d{1,2}, 20\d{2})", text)
    if m:
        out["updated"] = m.group(1)

    for table in soup.find_all("table"):
        headers = [cell_text(th).lower() for th in table.find_all("th")]
        if headers[:2] == ["version", "date"]:
            revs = []
            for tr in table.find_all("tr"):
                cells = [cell_text(td) for td in tr.find_all("td")]
                if len(cells) >= 2:
                    revs.append({"version": cells[0], "date": cells[1],
                                 "notes": cells[2] if len(cells) > 2 else ""})
            if revs:
                out["revisions"] = revs
                out["revision_count"] = len(revs)
                out["latest_revision"] = revs[-1]
            break

    return out


def fetch_bulletin():
    for slug in bulletin_months():
        url = f"{BULLETIN_INDEX}/{slug[:4]}/{slug}"
        try:
            r = requests.get(url, headers=UA, timeout=30)
        except requests.RequestException:
            continue
        if r.status_code == 404:
            continue
        r.raise_for_status()

        soup = BeautifulSoup(r.text, "html.parser")
        levels = sorted(set(PATCH_LEVEL_RE.findall(soup.get_text(" ", strip=True))))
        if not levels:
            continue

        rows = parse_tables(soup)
        mainline = {r["cve"] for r in rows if r.get("mainline")}
        cves = {}
        for row in rows:
            if row.get("mainline"):
                continue
            cves.setdefault(row["cve"], row)
        cve_rows = list(cves.values())

        newest = levels[-1]
        age = (today() - parse_date(newest)).days

        by_level = defaultdict(list)
        for row in cve_rows:
            by_level[row["patch_level"] or "unassigned"].append(row)

        def summarize(rows_):
            sev = Counter(r["severity"] for r in rows_)
            typ = Counter(r["type"] for r in rows_ if r["type"])
            return {
                "cve_count": len(rows_),
                "by_severity": {s: sev.get(s, 0) for s in SEVERITIES + ("Unknown",)},
                "by_type": {t: typ.get(t, 0) for t in TYPES},
                "critical_cves": sorted(r["cve"] for r in rows_
                                        if r["severity"] == "Critical"),
            }

        branches = sorted(
            {b for r in cve_rows for b in r["branches"]},
            key=lambda b: (int(re.match(r"\d+", b).group()) if re.match(r"\d+", b) else 0, b),
        )

        by_component = Counter(r["component"] for r in cve_rows)

        critical_rce = sorted(
            r["cve"] for r in cve_rows
            if r["severity"] == "Critical" and r["type"] == "RCE"
        )

        bulletin = {
            "month": slug,
            "url": url,
            "patch_levels": levels,
            "latest_spl": newest,
            "latest_spl_age_days": age,
            "latest_spl_age_months": round(age / 30.4, 1),
            "cve_total": len(cve_rows),
            "by_patch_level": {lvl: summarize(rws) for lvl, rws in sorted(by_level.items())},
            "by_severity": {s: c for s, c in
                            Counter(r["severity"] for r in cve_rows).items()},
            "by_type": {t: c for t, c in
                        Counter(r["type"] for r in cve_rows if r["type"]).items()},
            "by_component": dict(by_component.most_common()),
            "branches_patched": branches,
            "critical_rce_cves": critical_rce,
            "mainline_cves": sorted(mainline),
            "mainline_count": len(mainline),
        }
        bulletin.update(parse_revisions(soup))

        return bulletin, cve_rows

    raise RuntimeError("No usable bulletin page found")


# --------------------------------------------------------------------- KEV

def kev_block(cve_list):
    r = requests.get(KEV_FEED, headers=UA, timeout=60)
    r.raise_for_status()
    catalog = r.json()
    vulns = catalog.get("vulnerabilities", [])

    index = {v["cveID"]: v for v in vulns}
    hits = [{
        "cve": cve,
        "vendor": index[cve].get("vendorProject"),
        "product": index[cve].get("product"),
        "due_date": index[cve].get("dueDate"),
    } for cve in cve_list if cve in index]

    android_total = sum(
        1 for v in vulns
        if "android" in (str(v.get("product", "")) + str(v.get("vendorProject", ""))).lower()
    )

    return {
        "matches_this_month": hits,
        "match_count": len(hits),
        "catalog_date": catalog.get("dateReleased"),
        "android_entries_total": android_total,
    }


# ----------------------------------------------------------------- history

def load_previous():
    if not os.path.exists(OUT_FILE):
        return None
    try:
        with open(OUT_FILE) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def build_history(previous, bulletin):
    history = list(previous.get("history", [])) if previous else []
    entry = {
        "month": bulletin["month"],
        "spl": bulletin["latest_spl"],
        "cve_total": bulletin["cve_total"],
        "critical": bulletin.get("by_severity", {}).get("Critical", 0),
    }
    history = [h for h in history if h.get("month") != entry["month"]]
    history.append(entry)
    history.sort(key=lambda h: h["month"], reverse=True)
    return history[:HISTORY_MONTHS]


def next_bulletin_expected():
    """Bulletins land in the first week of the month; use the 1st as the anchor."""
    d = today().replace(day=1)
    nxt = (d + timedelta(days=32)).replace(day=1)
    return nxt.isoformat()


# -------------------------------------------------------------------- main

def main():
    previous = load_previous()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    feed = {
        "generated": now,
        "schema": 4,
        "sources": {
            "versions": EOL_API,
            "bulletin_index": BULLETIN_INDEX,
            "kev": KEV_FEED,
        },
    }

    try:
        majors, supported = build_majors()
    except Exception as exc:
        print(f"version lookup failed: {exc}", file=sys.stderr)
        sys.exit(1)

    feed["latest_major"] = supported[0] if supported else None
    feed["supported_majors"] = supported
    feed["n_minus_2_floor"] = supported[2] if len(supported) > 2 else (
        supported[-1] if supported else None)

    cve_rows = []
    try:
        bulletin, cve_rows = fetch_bulletin()
        feed["bulletin"] = bulletin
        feed["latest_spl"] = bulletin["latest_spl"]
        feed["latest_spl_age_days"] = bulletin["latest_spl_age_days"]
        feed["history"] = build_history(previous, bulletin)
    except Exception as exc:
        print(f"bulletin lookup failed: {exc}", file=sys.stderr)
        feed["bulletin_error"] = str(exc)
        if previous:
            feed["history"] = previous.get("history", [])

    # attach this month's exposure to each major
    if cve_rows:
        for m in majors:
            v = m["version"]
            mine = [r for r in cve_rows
                    if any(b == v or b.startswith(f"{v}-") for b in r["branches"])]
            m["cves_this_month"] = len(mine)
            m["criticals_this_month"] = sum(1 for r in mine if r["severity"] == "Critical")
            m["branches_in_bulletin"] = sorted(
                {b for r in mine for b in r["branches"]
                 if b == v or b.startswith(f"{v}-")}
            )
    feed["majors"] = majors

    if cve_rows:
        try:
            feed["kev"] = kev_block([r["cve"] for r in cve_rows])
        except Exception as exc:
            print(f"KEV lookup failed: {exc}", file=sys.stderr)
            feed["kev_error"] = str(exc)

    # urgency: criticals are routine, exploitation and critical RCE are not
    kev_hits = feed.get("kev", {}).get("match_count", 0)
    critical_rce = len(feed.get("bulletin", {}).get("critical_rce_cves", []))
    if kev_hits:
        feed["urgency"] = "urgent"
    elif critical_rce:
        feed["urgency"] = "elevated"
    else:
        feed["urgency"] = "routine"
    feed["act_now"] = feed["urgency"] != "routine"

    feed["next_bulletin_expected"] = next_bulletin_expected()

    with open(OUT_FILE, "w") as fh:
        json.dump(feed, fh, indent=2)

    print(json.dumps(feed, indent=2)[:4000])


if __name__ == "__main__":
    main()
