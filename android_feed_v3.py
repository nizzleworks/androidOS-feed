#!/usr/bin/env python3
"""
Android release intelligence feed - v3.

Adds to v2:
  - CVE counts by severity from the monthly bulletin
  - affected AOSP versions per patch level
  - CISA KEV matches (known exploited vulnerabilities)
  - a simple "act now" flag

Run:  python3 android_feed_v3.py
Out:  android_feed.json

Deps: pip install requests beautifulsoup4
"""

import json
import re
import sys
from collections import Counter
from datetime import date, datetime, timezone

import requests
from bs4 import BeautifulSoup

EOL_API = "https://endoflife.date/api/android.json"
BULLETIN_INDEX = "https://source.android.com/docs/security/bulletin"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = {"User-Agent": "android-feed/0.3 (nizzleworks)"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SEVERITIES = ("Critical", "High", "Moderate", "Low")


# ---------------------------------------------------------------- versions

def is_eol(eol_value):
    if eol_value in (None, False):
        return False
    if eol_value is True:
        return True
    try:
        return datetime.strptime(eol_value, "%Y-%m-%d").date() <= date.today()
    except (TypeError, ValueError):
        return False


def latest_version():
    r = requests.get(EOL_API, headers=UA, timeout=30)
    r.raise_for_status()
    cycles = r.json()

    newest = cycles[0]
    supported = [c["cycle"] for c in cycles if not is_eol(c.get("eol"))]

    return {
        "latest_major": newest["cycle"],
        "latest_release_date": newest.get("releaseDate"),
        "supported_majors": supported,
        "n_minus_2_floor": supported[2] if len(supported) > 2 else supported[-1],
    }


# ---------------------------------------------------------------- bulletin

def bulletin_months_from_index():
    r = requests.get(BULLETIN_INDEX, headers=UA, timeout=30)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    months = set()
    for a in soup.find_all("a", href=True):
        m = re.search(r"/bulletin/20\d{2}/(20\d{2}-\d{2}-01)", a["href"])
        if m:
            months.add(m.group(1))
    return sorted(months)


def candidate_months_from_today():
    today = date.today()
    out = []
    y, m = today.year, today.month
    for _ in range(3):
        out.append(f"{y:04d}-{m:02d}-01")
        m -= 1
        if m == 0:
            m, y = 12, y - 1
    return out


def parse_bulletin(soup):
    """Walk every table on the bulletin and pull CVE rows.

    Bulletin tables vary, but the header row reliably contains 'CVE'
    and usually 'Severity' and 'Updated AOSP versions'. We map columns
    by header name rather than position so a column reorder doesn't
    silently give wrong data.
    """
    rows = []
    for table in soup.find_all("table"):
        headers = [th.get_text(" ", strip=True).lower()
                   for th in table.find_all("th")]
        if not headers or not any("cve" in h for h in headers):
            continue

        def col(*names):
            for i, h in enumerate(headers):
                if any(n in h for n in names):
                    return i
            return None

        i_cve = col("cve")
        i_sev = col("severity")
        i_ver = col("updated aosp", "aosp version", "versions")

        for tr in table.find_all("tr"):
            cells = tr.find_all("td")
            if not cells or i_cve is None or i_cve >= len(cells):
                continue

            cve_match = CVE_RE.search(cells[i_cve].get_text(" ", strip=True))
            if not cve_match:
                continue

            severity = ""
            if i_sev is not None and i_sev < len(cells):
                severity = cells[i_sev].get_text(" ", strip=True).title()

            versions = []
            if i_ver is not None and i_ver < len(cells):
                versions = re.findall(r"\b(\d{1,2})(?:\.\d+)*\b",
                                      cells[i_ver].get_text(" ", strip=True))

            rows.append({
                "cve": cve_match.group(0),
                "severity": severity if severity in SEVERITIES else "Unknown",
                "versions": sorted({v for v in versions if 5 <= int(v) <= 30}),
            })

    # de-duplicate: the same CVE can appear in more than one table
    seen = {}
    for row in rows:
        seen.setdefault(row["cve"], row)
    return list(seen.values())


def patch_levels_on_page(month_slug):
    url = f"{BULLETIN_INDEX}/{month_slug[:4]}/{month_slug}"
    r = requests.get(url, headers=UA, timeout=30)
    if r.status_code == 404:
        return url, None, []
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    text = soup.get_text(" ", strip=True)
    levels = sorted(set(re.findall(r"\b(20\d{2}-\d{2}-0[15])\b", text)))
    return url, soup, levels


def latest_bulletin():
    months = sorted(
        set(bulletin_months_from_index()) | set(candidate_months_from_today()),
        reverse=True,
    )

    errors = []
    for slug in months:
        try:
            url, soup, levels = patch_levels_on_page(slug)
        except requests.RequestException as exc:
            errors.append(f"{slug}: {exc}")
            continue
        if not levels:
            continue

        newest = levels[-1]
        age_days = (date.today() - datetime.strptime(newest, "%Y-%m-%d").date()).days
        cves = parse_bulletin(soup)

        severity_counts = Counter(c["severity"] for c in cves)
        affected = sorted(
            {v for c in cves for v in c["versions"]},
            key=lambda v: int(v),
        )

        return {
            "latest_spl": newest,
            "patch_levels": levels,
            "latest_spl_age_days": age_days,
            "latest_spl_age_months": round(age_days / 30.4, 1),
            "bulletin_month": slug,
            "bulletin_url": url,
            "cve_total": len(cves),
            "cve_by_severity": {s: severity_counts.get(s, 0)
                                for s in SEVERITIES + ("Unknown",)},
            "critical_cves": sorted(c["cve"] for c in cves
                                    if c["severity"] == "Critical"),
            "affected_aosp_versions": affected,
            "_cve_list": [c["cve"] for c in cves],  # stripped before output
        }

    raise RuntimeError(
        "No patch levels found on any recent bulletin page. "
        f"Tried: {', '.join(months[:6])}. {' | '.join(errors)}"
    )


# --------------------------------------------------------------------- KEV

def kev_matches(cve_list):
    """Which of this month's CVEs are in CISA's known-exploited catalog."""
    r = requests.get(KEV_FEED, headers=UA, timeout=60)
    r.raise_for_status()
    catalog = r.json()

    kev_index = {v["cveID"]: v for v in catalog.get("vulnerabilities", [])}
    hits = []
    for cve in cve_list:
        entry = kev_index.get(cve)
        if entry:
            hits.append({
                "cve": cve,
                "vendor": entry.get("vendorProject"),
                "product": entry.get("product"),
                "due_date": entry.get("dueDate"),
            })

    # Android-related KEV entries overall, useful context even when this
    # month's bulletin has no matches
    android_kev = [
        v["cveID"] for v in catalog.get("vulnerabilities", [])
        if "android" in (v.get("product", "") + v.get("vendorProject", "")).lower()
    ]

    return {
        "kev_matches_this_month": hits,
        "kev_match_count": len(hits),
        "kev_catalog_date": catalog.get("dateReleased"),
        "android_kev_total": len(android_kev),
    }


# -------------------------------------------------------------------- main

def main():
    feed = {
        "generated": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "schema": 3,
    }

    try:
        feed.update(latest_version())
    except Exception as exc:
        print(f"version lookup failed: {exc}", file=sys.stderr)
        sys.exit(1)

    cve_list = []
    try:
        bulletin = latest_bulletin()
        cve_list = bulletin.pop("_cve_list", [])
        feed.update(bulletin)
    except Exception as exc:
        print(f"bulletin lookup failed: {exc}", file=sys.stderr)
        feed["bulletin_error"] = str(exc)

    if cve_list:
        try:
            feed.update(kev_matches(cve_list))
        except Exception as exc:
            print(f"KEV lookup failed: {exc}", file=sys.stderr)
            feed["kev_error"] = str(exc)

    # simple triage flag for the app / widget
    feed["act_now"] = bool(
        feed.get("kev_match_count") or feed.get("cve_by_severity", {}).get("Critical")
    )

    with open("android_feed.json", "w") as fh:
        json.dump(feed, fh, indent=2)

    print(json.dumps(feed, indent=2))


if __name__ == "__main__":
    main()
