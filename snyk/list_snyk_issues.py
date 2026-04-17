#!/usr/bin/env python3
"""
List or fetch a single issue via the Snyk REST Issues API (JSON).

Auth (same as export_snyk_issue_urls.py):
  SNYK_TOKEN, or --token-file, or ~/.snyk/snyk_token

Examples:
  export SNYK_TOKEN='...'
  export SNYK_ORG_ID='...'
  python3 scripts/list_snyk_issues.py
  python3 scripts/list_snyk_issues.py --limit 50 --all-pages -o issues.json
  python3 scripts/list_snyk_issues.py --issue-id 73832c6c-19ff-4a92-850c-2e1ff2800c16

  # Add attributes.issue_ui_url (after key) for deep links (undocumented pattern):
  export SNYK_ORG_SLUG='my-org-slug'
  python3 scripts/list_snyk_issues.py -o issues-with-urls.json

API reference:
  https://docs.snyk.io/snyk-api/reference/issues

Note: issue_ui_url is assembled as
  https://app.snyk.io/org/<slug>/project/<project_id>#issue-<attributes.key>
Validate per issue type; Export ISSUE_URL remains the supported bulk link.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# OpenAPI tags this resource with x-snyk-api-version 2024-01-23 (listOrgIssues).
DEFAULT_ISSUES_API_VERSION = "2024-01-23"


def _read_token(args: argparse.Namespace) -> str:
    if args.token_file:
        return Path(args.token_file).expanduser().read_text(encoding="utf-8").strip()
    env = os.environ.get("SNYK_TOKEN", "").strip()
    if env:
        return env
    fallback = Path.home() / ".snyk" / "snyk_token"
    if fallback.is_file():
        return fallback.read_text(encoding="utf-8").strip()
    sys.stderr.write(
        "No token: set SNYK_TOKEN, use --token-file, or create ~/.snyk/snyk_token\n"
    )
    sys.exit(2)


def _request(
    method: str,
    url: str,
    token: str,
) -> tuple[int, dict[str, Any] | list[Any] | None, str]:
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
    }
    req = urllib.request.Request(url, headers=headers, method=method)
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


def _die(msg: str, status: int, parsed: Any, raw: str) -> None:
    sys.stderr.write(f"{msg}: HTTP {status}\n")
    if parsed is not None:
        sys.stderr.write(json.dumps(parsed, indent=2)[:12000] + "\n")
    else:
        sys.stderr.write(raw[:12000] + "\n")
    sys.exit(1)


def _abs_link(api_base: str, link: str) -> str:
    if link.startswith("http://") or link.startswith("https://"):
        return link
    base = api_base.rstrip("/")
    if link.startswith("/rest/"):
        root = base[: -len("/rest")] if base.endswith("/rest") else base
        return root + link
    if link.startswith("/"):
        return base + link
    return f"{base}/{link}"


def _project_id_from_issue(issue: dict[str, Any]) -> str | None:
    scan = (issue.get("relationships") or {}).get("scan_item") or {}
    data = scan.get("data")
    if not isinstance(data, dict):
        return None
    if data.get("type") != "project":
        return None
    pid = data.get("id")
    return str(pid) if pid else None


def _enrich_issue_with_ui_url(issue: dict[str, Any], org_slug: str) -> dict[str, Any]:
    """Deep-copy one issue and insert attributes.issue_ui_url immediately after key."""
    out: dict[str, Any] = json.loads(json.dumps(issue))
    attrs = out.get("attributes")
    if not isinstance(attrs, dict):
        return out
    key = attrs.get("key")
    project_id = _project_id_from_issue(out)
    org_slug = org_slug.strip()
    issue_ui_url: str | None = None
    if org_slug and project_id and key is not None and str(key).strip() != "":
        issue_ui_url = (
            f"https://app.snyk.io/org/{org_slug}/project/{project_id}#issue-{key}"
        )

    new_attrs: dict[str, Any] = {}
    inserted = False
    for k, v in attrs.items():
        new_attrs[k] = v
        if k == "key" and issue_ui_url is not None:
            new_attrs["issue_ui_url"] = issue_ui_url
            inserted = True
    if issue_ui_url is not None and not inserted:
        new_attrs["issue_ui_url"] = issue_ui_url
    out["attributes"] = new_attrs
    return out


def _enrich_payload_issues(payload: dict[str, Any], org_slug: str) -> dict[str, Any]:
    if not org_slug.strip():
        return payload
    out = json.loads(json.dumps(payload))
    data = out.get("data")
    if isinstance(data, list):
        out["data"] = [_enrich_issue_with_ui_url(i, org_slug) for i in data if isinstance(i, dict)]
    elif isinstance(data, dict):
        out["data"] = _enrich_issue_with_ui_url(data, org_slug)
    return out


def _print_summary(payload: dict[str, Any]) -> None:
    rows = payload.get("data")
    if not isinstance(rows, list):
        return
    for item in rows:
        if not isinstance(item, dict):
            continue
        iid = item.get("id", "")
        attrs = item.get("attributes") or {}
        title = (attrs.get("title") or attrs.get("description") or "")[:80]
        status = attrs.get("status", "")
        sev = attrs.get("effective_severity_level", "")
        print(f"{iid}\t{status}\t{sev}\t{title}")


def cmd_list_orgs(base: str, token: str) -> None:
    # /orgs listing follows the general REST version (see getting-started docs).
    url = f"{base.rstrip('/')}/orgs?version=2024-10-15&limit=100"
    status, parsed, raw = _request("GET", url, token)
    if status != 200 or not isinstance(parsed, dict):
        _die("List orgs", status, parsed, raw)
    for row in parsed.get("data") or []:
        if not isinstance(row, dict):
            continue
        oid = row.get("id", "")
        attrs = row.get("attributes") or {}
        print(f"{oid}\t{attrs.get('slug', '')}\t{attrs.get('name', '')}")


def main() -> None:
    p = argparse.ArgumentParser(description="Snyk Issues REST API (JSON)")
    p.add_argument("--api-base", default=os.environ.get("SNYK_API_BASE", "https://api.snyk.io/rest"))
    p.add_argument(
        "--api-version",
        default=os.environ.get("SNYK_ISSUES_API_VERSION", DEFAULT_ISSUES_API_VERSION),
        help="?version= for Issues endpoints (OpenAPI default for listOrgIssues)",
    )
    p.add_argument("--org-id", default=os.environ.get("SNYK_ORG_ID", ""))
    p.add_argument("--token-file", default=None)
    p.add_argument("--list-orgs", action="store_true")
    p.add_argument("--issue-id", default="", help="Fetch one issue by UUID")
    p.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Page size (OpenAPI: 10–100, multiple of 10)",
    )
    p.add_argument(
        "--all-pages",
        action="store_true",
        help="Follow JSON:API links.next until exhausted",
    )
    p.add_argument(
        "--summary",
        action="store_true",
        help="Print id, status, severity, title per issue to stdout (in addition to JSON if -o set)",
    )
    p.add_argument("--updated-after", default="", help="ISO8601 filter")
    p.add_argument("--updated-before", default="", help="ISO8601 filter")
    p.add_argument(
        "--status",
        action="append",
        choices=("open", "resolved"),
        default=None,
        help="Repeatable: --status open --status resolved",
    )
    p.add_argument(
        "--effective-severity-level",
        action="append",
        dest="sev",
        choices=("info", "low", "medium", "high", "critical"),
        default=None,
    )
    p.add_argument(
        "--ignored",
        choices=("true", "false"),
        default=None,
        help="Filter ignored issues",
    )
    p.add_argument("-o", "--output", type=Path, default=None, help="Write combined JSON here")
    p.add_argument(
        "--org-slug",
        default=os.environ.get("SNYK_ORG_SLUG", ""),
        help="Snyk org slug (URL segment) — adds attributes.issue_ui_url after key",
    )
    args = p.parse_args()
    token = _read_token(args)
    base = args.api_base.rstrip("/")
    ver = args.api_version

    if args.list_orgs:
        cmd_list_orgs(base, token)
        return

    org_id = (args.org_id or "").strip()
    if not org_id:
        sys.stderr.write("Set SNYK_ORG_ID or --org-id (or use --list-orgs).\n")
        sys.exit(2)

    lim = args.limit
    if lim % 10 != 0 or lim < 10 or lim > 100:
        sys.stderr.write("Warning: OpenAPI expects limit in [10,100] and multiple of 10; continuing.\n")

    if args.issue_id.strip():
        url = f"{base}/orgs/{org_id}/issues/{args.issue_id.strip()}?version={urllib.parse.quote(ver)}"
        status, parsed, raw = _request("GET", url, token)
        if status != 200 or not isinstance(parsed, dict):
            _die("Get issue", status, parsed, raw)
        parsed = _enrich_payload_issues(parsed, args.org_slug)
        text = json.dumps(parsed, indent=2)
        print(text)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        return

    q: list[tuple[str, str]] = [("version", ver), ("limit", str(lim))]
    if args.updated_after:
        q.append(("updated_after", args.updated_after))
    if args.updated_before:
        q.append(("updated_before", args.updated_before))
    if args.status:
        for s in args.status:
            q.append(("status", s))
    if args.sev:
        for s in args.sev:
            q.append(("effective_severity_level", s))
    if args.ignored is not None:
        q.append(("ignored", args.ignored))

    url = f"{base}/orgs/{org_id}/issues?{urllib.parse.urlencode(q)}"
    combined: dict[str, Any] = {"data": [], "links": {}, "meta": {}}
    first_meta: dict[str, Any] | None = None

    while True:
        status, parsed, raw = _request("GET", url, token)
        if status != 200 or not isinstance(parsed, dict):
            _die("List issues", status, parsed, raw)

        chunk = parsed.get("data")
        if isinstance(chunk, list):
            combined["data"].extend(chunk)
        if first_meta is None:
            first_meta = parsed.get("meta") if isinstance(parsed.get("meta"), dict) else {}
            combined["meta"] = first_meta or {}
        combined["links"] = parsed.get("links") or combined["links"]

        if args.summary:
            _print_summary(parsed)

        nxt = (parsed.get("links") or {}).get("next")
        if not args.all_pages or not nxt or not isinstance(nxt, str):
            break
        url = _abs_link(base, nxt)

    out_obj = {"data": combined["data"], "links": combined["links"], "meta": combined["meta"]}
    out_obj = _enrich_payload_issues(out_obj, args.org_slug)
    text = json.dumps(out_obj, indent=2)
    if not args.summary or args.output:
        print(text)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"Wrote {args.output.resolve()} ({len(combined['data'])} issues)", file=sys.stderr)


if __name__ == "__main__":
    main()
