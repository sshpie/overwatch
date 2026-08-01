"""overwatch CLI — three verbs over the passive observer.

  overwatch tabs                       list open Chrome targets (needs :9222)
  overwatch watch --tab <id|url-substr> ride one tab, live taxonomy scan
  overwatch scan-har capture.har       run the taxonomy over a saved HAR (offline)

The watch verb enforces a wall-clock budget (--seconds) and a hard exchange cap
so a run always terminates. Everything the observer sends is a browser read
(Network.enable / getResponseBody); nothing reaches the target app.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .cdp import discover_targets, CDPObserver, exchanges_from_har
from .detectors import run_detectors
from .ledger import Ledger


def _resolve_tab(targets, selector: str):
    """Match a target by exact id, then by url/title substring."""
    for t in targets:
        if t.get("id") == selector:
            return t
    for t in targets:
        hay = (t.get("url", "") + " " + t.get("title", "")).lower()
        if selector.lower() in hay:
            return t
    return None


def cmd_tabs(args):
    try:
        targets = discover_targets(args.host, args.port)
    except Exception as e:
        print(f"overwatch: cannot reach CDP at {args.host}:{args.port} — {e}", file=sys.stderr)
        print("  start Chrome with:  chrome --remote-debugging-port=9222", file=sys.stderr)
        return 2
    pages = [t for t in targets if t.get("type") == "page"]
    if not pages:
        print("overwatch: no page targets open")
        return 0
    for t in pages:
        print(f"  {t.get('id')}  {t.get('title','')[:40]:40}  {t.get('url','')[:80]}")
    return 0


def cmd_watch(args):
    try:
        targets = discover_targets(args.host, args.port)
    except Exception as e:
        print(f"overwatch: cannot reach CDP at {args.host}:{args.port} — {e}", file=sys.stderr)
        return 2
    pages = [t for t in targets if t.get("type") == "page"]
    target = _resolve_tab(pages, args.tab) if args.tab else (pages[0] if pages else None)
    if not target:
        print(f"overwatch: no tab matched '{args.tab}'", file=sys.stderr)
        return 2
    ws_url = target.get("webSocketDebuggerUrl")
    if not ws_url:
        print("overwatch: target has no webSocketDebuggerUrl (already attached?)", file=sys.stderr)
        return 2

    print(f"overwatch: riding  {target.get('title','')[:50]}  ({target.get('url','')[:60]})",
          file=sys.stderr)
    print(f"overwatch: passive only — {args.seconds}s budget, {args.max} exchange cap\n",
          file=sys.stderr)

    ledger = Ledger()
    obs = CDPObserver(ws_url)
    deadline = time.monotonic() + args.seconds
    seen = 0
    try:
        for ex in obs.watch(seconds=args.seconds, max_exchanges=args.max):
            seen += 1
            for f in run_detectors(ex):          # run the taxonomy once per exchange
                is_new = ledger.add(f)
                if is_new and not args.json:      # stream only first-seen findings, redacted
                    r = f.redacted()
                    print(f"  [+] [{r.severity}] {r.title}  — {r.url[:70]}", file=sys.stderr)
            if time.monotonic() >= deadline:
                break
    except KeyboardInterrupt:
        print("\noverwatch: interrupted — reporting what was seen", file=sys.stderr)

    print(f"\noverwatch: observed {seen} exchanges\n", file=sys.stderr)
    if args.json:
        print(ledger.to_json())
    else:
        print(ledger.render())
    return 0


def cmd_scan_har(args):
    try:
        with open(args.har, "r", encoding="utf-8") as fh:
            har = json.load(fh)
    except Exception as e:
        print(f"overwatch: cannot read HAR {args.har} — {e}", file=sys.stderr)
        return 2
    ledger = Ledger()
    n = 0
    for ex in exchanges_from_har(har):
        n += 1
        ledger.add_all(run_detectors(ex))
    print(f"overwatch: scanned {n} exchanges from {args.har}\n", file=sys.stderr)
    if args.json:
        print(ledger.to_json())
    else:
        print(ledger.render())
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="overwatch",
        description="Passive web-app assessment by riding a real authenticated session (CDP).",
    )
    p.add_argument("--host", default="127.0.0.1", help="CDP host (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=9222, help="CDP port (default 9222)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp_tabs = sub.add_parser("tabs", help="list open Chrome page targets")
    sp_tabs.set_defaults(func=cmd_tabs)

    sp_watch = sub.add_parser("watch", help="ride one tab and run the live taxonomy")
    sp_watch.add_argument("--tab", help="target id or url/title substring (default: first page)")
    sp_watch.add_argument("--seconds", type=int, default=120, help="wall-clock budget (default 120)")
    sp_watch.add_argument("--max", type=int, default=5000, help="hard exchange cap (default 5000)")
    sp_watch.add_argument("--json", action="store_true", help="emit JSON ledger instead of text")
    sp_watch.set_defaults(func=cmd_watch)

    sp_har = sub.add_parser("scan-har", help="run the taxonomy over a saved HAR (offline)")
    sp_har.add_argument("har", help="path to a .har capture")
    sp_har.add_argument("--json", action="store_true", help="emit JSON ledger instead of text")
    sp_har.set_defaults(func=cmd_scan_har)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
