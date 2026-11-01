"""Command line: ``headerscope URL`` grades a site's HTTP security headers.

    headerscope example.com
    headerscope https://a.example https://b.example --json
    cat urls.txt | headerscope --summary

Exit status: 0 when no URL has a failing header (and all were reachable), 1 when
any does or can't be reached, 2 for a bad call.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from typing import Optional, Sequence

from . import __version__
from .audit import Report, inspect


def _build_parser():
    import argparse

    p = argparse.ArgumentParser(prog="headerscope", description="Audit a site's HTTP security headers.")
    p.add_argument("urls", nargs="*", help="URLs to check (default: read from stdin)")
    p.add_argument("-t", "--timeout", type=float, default=10.0, metavar="S", help="request timeout (default: 10)")
    p.add_argument("-k", "--insecure", action="store_true", help="do not verify the TLS certificate")
    p.add_argument("-s", "--summary", action="store_true", help="print only the grade line per URL")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("-V", "--version", action="version", version=f"headerscope {__version__}")
    return p


_SYMBOL = {"ok": "ok  ", "warn": "warn", "fail": "fail"}


def _print(report: Report, summary: bool) -> None:
    if report.error:
        print(f"{report.url}  ERROR: {report.error}")
        return
    print(f"{report.url}  {report.grade} ({report.score})  {report.fails} fail, {report.warns} warn")
    if summary:
        return
    width = max((len(f.header) for f in report.findings), default=0)
    for f in report.findings:
        print(f"  {_SYMBOL[f.status]}  {f.header.ljust(width)}  {f.detail}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    targets = args.urls or [line.strip() for line in sys.stdin if line.strip()]
    if not targets:
        print("headerscope: no URLs given", file=sys.stderr)
        return 2

    reports = [inspect(url, timeout=args.timeout, insecure=args.insecure) for url in targets]

    if args.json:
        print(json.dumps([{**dataclasses.asdict(r), "ok": r.ok} for r in reports], indent=2))
    else:
        for i, report in enumerate(reports):
            if i:
                print()
            _print(report, args.summary)

    return 0 if all(r.ok for r in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
