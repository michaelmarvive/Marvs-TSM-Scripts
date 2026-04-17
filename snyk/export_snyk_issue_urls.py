#!/usr/bin/env python3
"""
Export Snyk issues via the Dataset Export API and save a CSV containing ISSUE_URL
(project-scoped links in the Snyk UI).

Authentication (pick one):
  - SNYK_TOKEN environment variable (recommended)
  - --token-file PATH (single line, no newline issues)
  - ~/.snyk/snyk_token (single line) if present

Organization:
  - SNYK_ORG_ID (UUID from Org Settings → General), or
  - --org-id UUID, or
  - --list-orgs to print org UUIDs available to this token

API host (region):
  - SNYK_API_BASE (default: https://api.snyk.io/rest)

Example:
  export SNYK_TOKEN="$(pbpaste)"
  export SNYK_ORG_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  python3 scripts/export_snyk_issue_urls.py --output ./snyk-issues.csv

Docs:
  https://docs.snyk.io/snyk-api/using-specific-snyk-apis/export-api-specifications-columns-and-filters
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

API_VERSION = "2024-10-15"
DEFAULT_COLUMNS = [
    "ISSUE_URL",
    "PROJECT_NAME",
    "PROJECT_PUBLIC_ID",
    "PROBLEM_TITLE",
    "ISSUE_SEVERITY",
    "ISSUE_STATUS",
    "PRODUCT_NAME",
    "ISSUE_TYPE",
    "FILE_PATH",
    "CODE_REGION",
    "CVE",
    "VULN_DB_URL",
]


def _read_token(args: argparse.Namespace) -> str:
    if args.token_file:
        p = Path(args.token_file).expanduser()
        return p.read_text(encoding="utf-8").strip()
    env = os.environ.get("SNYK_TOKEN", "").strip()
    if env:
        return env
    fallback = Path.home() / ".snyk" / "snyk_token"
    if fallback.is_file():
        return fallback.read_text(encoding="utf-8").strip()
    sys.stderr.write(
        "No token found. Set SNYK_TOKEN, use --token-file, or create ~/.snyk/snyk_token\n"
    )
    sys.exit(2)


def _request(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | list[Any] | None, str]:
    data = None
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status
            if not raw:
                return status, None, raw
            return status, json.loads(raw), raw
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(err_body) if err_body else None
        except json.JSONDecodeError:
            parsed = None
        return e.code, parsed, err_body


def _die_http(action: str, status: int, parsed: Any, raw: str) -> None:
    sys.stderr.write(f"{action} failed: HTTP {status}\n")
    if parsed is not None:
        sys.stderr.write(json.dumps(parsed, indent=2)[:8000] + "\n")
    else:
        sys.stderr.write(raw[:8000] + "\n")
    sys.exit(1)


def _extract_export_id(parsed: dict[str, Any]) -> str:
    try:
        return str(parsed["data"]["id"])
    except (KeyError, TypeError) as e:
        sys.stderr.write(f"Unexpected create-export response: {parsed!r}\n")
        raise SystemExit(1) from e


def _job_status_url_from_create(base: str, parsed: dict[str, Any], org_id: str, export_id: str) -> str:
    """Prefer links.self from POST response; else org default.

    Org scope uses ``/orgs/{id}/export/jobs/{export_id}`` (see links.self examples in Snyk OpenAPI).
    Group scope uses ``/groups/{id}/jobs/export/{export_id}`` — do not mix them up.
    """
    self_link = (parsed.get("data") or {}).get("links") or {}
    if isinstance(self_link, dict):
        path = self_link.get("self")
        if isinstance(path, str) and path.startswith("/"):
            return f"{base}{path}?version={API_VERSION}"
    return f"{base}/orgs/{org_id}/export/jobs/{export_id}?version={API_VERSION}"


def _org_job_status_url_candidates(
    base: str, parsed: dict[str, Any], org_id: str, export_id: str
) -> list[str]:
    """Ordered list of URLs to try when polling export job status (org scope)."""
    primary = _job_status_url_from_create(base, parsed, org_id, export_id)
    legacy = f"{base}/orgs/{org_id}/jobs/export/{export_id}?version={API_VERSION}"
    out = [primary]
    if legacy not in out:
        out.append(legacy)
    return out


def _collect_signed_urls(obj: Any) -> list[str]:
    """Pull https URLs from export results blobs (schema varies slightly)."""
    found: list[str] = []

    def walk(x: Any) -> None:
        if isinstance(x, str) and x.startswith("https://"):
            found.append(x)
        elif isinstance(x, dict):
            for k, v in x.items():
                if k in ("url", "download_url", "href", "signed_url") and isinstance(v, str):
                    if v.startswith("https://"):
                        found.append(v)
                walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)

    walk(obj)
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _download_url(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=600) as resp:
        dest.write_bytes(resp.read())


def cmd_list_orgs(base: str, token: str) -> None:
    url = f"{base.rstrip('/')}/orgs?version={API_VERSION}&limit=100"
    status, parsed, raw = _request("GET", url, token)
    if status != 200 or not isinstance(parsed, dict):
        _die_http("List orgs", status, parsed, raw)
    for row in parsed.get("data") or []:
        oid = row.get("id", "")
        attrs = row.get("attributes") or {}
        name = attrs.get("name", "")
        slug = attrs.get("slug", "")
        print(f"{oid}\t{slug}\t{name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Snyk Export API: fetch issues CSV with ISSUE_URL")
    parser.add_argument(
        "--api-base",
        default=os.environ.get("SNYK_API_BASE", "https://api.snyk.io/rest"),
        help="REST API base (region-specific). Default or SNYK_API_BASE.",
    )
    parser.add_argument(
        "--org-id",
        default=os.environ.get("SNYK_ORG_ID", ""),
        help="Organization public UUID (SNYK_ORG_ID)",
    )
    parser.add_argument("--token-file", help="File containing API token / PAT (one line)")
    parser.add_argument(
        "--list-orgs",
        action="store_true",
        help="Print org id, slug, name for this token and exit",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("snyk-export-issues.csv"),
        help="Where to write the downloaded CSV",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=10.0,
        help="Interval while waiting for export to finish",
    )
    parser.add_argument(
        "--updated-from",
        default="2020-01-01T00:00:00Z",
        help="filters.updated.from (ISO8601 Z)",
    )
    parser.add_argument(
        "--updated-to",
        default="",
        help="filters.updated.to (default: now UTC)",
    )
    parser.add_argument(
        "--use-introduced-instead",
        action="store_true",
        help="Use introduced date range instead of updated (both from/to required)",
    )
    parser.add_argument(
        "--introduced-from",
        default="2020-01-01T00:00:00Z",
        help="filters.introduced.from when --use-introduced-instead",
    )
    parser.add_argument(
        "--introduced-to",
        default="",
        help="filters.introduced.to when --use-introduced-instead (default: now UTC)",
    )
    parser.add_argument(
        "--url-expiration-seconds",
        type=int,
        default=3600,
        help="Signed download URL lifetime (0–3600)",
    )
    args = parser.parse_args()
    token = _read_token(args)

    base = args.api_base.rstrip("/")

    if args.list_orgs:
        cmd_list_orgs(base, token)
        return

    org_id = (args.org_id or "").strip()
    if not org_id:
        sys.stderr.write(
            "Missing org id. Set SNYK_ORG_ID or pass --org-id, or run with --list-orgs.\n"
        )
        sys.exit(2)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if args.use_introduced_instead:
        to = args.introduced_to.strip() or now
        filters: dict[str, Any] = {
            "introduced": {"from": args.introduced_from, "to": to},
        }
    else:
        to = args.updated_to.strip() or now
        filters = {"updated": {"from": args.updated_from, "to": to}}

    create_url = f"{base}/orgs/{org_id}/export?version={API_VERSION}"
    payload = {
        "data": {
            "type": "export",
            "attributes": {
                "dataset": "issues",
                "formats": ["csv"],
                "filters": filters,
                "columns": DEFAULT_COLUMNS,
                "url_expiration_seconds": max(0, min(3600, args.url_expiration_seconds)),
            },
        },
    }

    status, parsed, raw = _request("POST", create_url, token, payload)
    if status not in (200, 201, 202) or not isinstance(parsed, dict):
        _die_http("Create export", status, parsed, raw)

    create_response = parsed
    export_id = _extract_export_id(create_response)
    print(f"Export started: {export_id}", file=sys.stderr)

    # Poll job status, then fetch results. Org scope uses /orgs/.../export/jobs/{id}
    # (not /orgs/.../jobs/export/..., which is the group-style path).
    results_url = f"{base}/orgs/{org_id}/export/{export_id}?version={API_VERSION}"
    job_candidates = _org_job_status_url_candidates(base, create_response, org_id, export_id)
    job_status_url: str | None = None
    last_fail: tuple[int, Any, str] = (404, None, "")

    while True:
        if job_status_url is None:
            for u in job_candidates:
                st, pr, rw = _request("GET", u, token)
                if st == 200 and isinstance(pr, dict):
                    job_status_url = u
                    status, parsed, raw = st, pr, rw
                    print(f"Using job status URL: {u.split('?')[0]}", file=sys.stderr)
                    break
                last_fail = (st, pr, rw)
                if st not in (404,):
                    _die_http("Poll export job status", st, pr, rw)
            else:
                sys.stderr.write("Tried job status URLs:\n")
                for u in job_candidates:
                    sys.stderr.write(f"  {u}\n")
                st, pr, rw = last_fail
                _die_http("Poll export job status (all candidates 404)", st, pr, rw)
        else:
            status, parsed, raw = _request("GET", job_status_url, token)
            if status != 200 or not isinstance(parsed, dict):
                _die_http("Poll export job status", status, parsed, raw)

        attrs = parsed.get("data", {}).get("attributes") or {}
        state = attrs.get("status", "")
        print(f"Job status: {state}", file=sys.stderr)
        if state == "FINISHED":
            break
        if state in ("ERRORED", "ERROR"):
            sys.stderr.write("Export failed. Full response:\n")
            sys.stderr.write(json.dumps(parsed, indent=2)[:8000] + "\n")
            sys.exit(1)
        time.sleep(args.poll_seconds)

    status, parsed, raw = _request("GET", results_url, token)
    if status != 200 or not isinstance(parsed, dict):
        _die_http("Get export results", status, parsed, raw)
    final = parsed.get("data", {}).get("attributes") or {}
    if final.get("status") not in (None, "FINISHED"):
        sys.stderr.write("Unexpected results payload:\n")
        sys.stderr.write(json.dumps(parsed, indent=2)[:8000] + "\n")
        sys.exit(1)

    urls = _collect_signed_urls(final.get("results"))
    if not urls:
        sys.stderr.write(
            "Export finished but no signed URL found in results. Raw attributes:\n"
            + json.dumps(final, indent=2)[:8000]
            + "\n"
        )
        sys.exit(1)

    signed = urls[0]
    if len(urls) > 1:
        print(f"Multiple download URLs returned; using first of {len(urls)}.", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading CSV → {args.output.resolve()}", file=sys.stderr)
    _download_url(signed, args.output)

    # Summarize ISSUE_URL column
    with args.output.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            print("CSV has no header row.", file=sys.stderr)
            return
        key = None
        for candidate in reader.fieldnames:
            if candidate and candidate.upper().replace(" ", "_") == "ISSUE_URL":
                key = candidate
                break
        if key is None:
            for candidate in reader.fieldnames:
                if "ISSUE" in candidate.upper() and "URL" in candidate.upper():
                    key = candidate
                    break
        n = 0
        sample: list[str] = []
        for row in reader:
            n += 1
            if key and row.get(key) and len(sample) < 3:
                sample.append(row[key].strip())
        print(f"Rows: {n}", file=sys.stderr)
        if key:
            print(f"Issue URL column: {key}", file=sys.stderr)
            for s in sample:
                print(s)
        else:
            print("Could not detect ISSUE_URL column; inspect CSV manually.", file=sys.stderr)


if __name__ == "__main__":
    main()
