"""CLI — scan repos, view dashboard, manage history."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import scan_target


def build_parser():
    p = argparse.ArgumentParser(
        prog="reporeaver",
        description="Security gate for repos. Answers: can this codebase safely be cloned, built, or run?",
        epilog="Examples:\n"
               "  reporeaver scan ./repo\n"
               "  reporeaver scan project.zip --verbose --html report.html\n"
               "  reporeaver dashboard\n"
               "  reporeaver history --last 10",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sub = p.add_subparsers(dest="command")
    sub.required = True

    # scan
    scan = sub.add_parser("scan", help="Scan a repo/dir/archive for threats")
    scan.add_argument("path", type=str)
    scan.add_argument("-v", "--verbose", action="store_true", help="Show medium-severity too")
    scan.add_argument("-j", "--json", action="store_true", dest="json_output")
    scan.add_argument("-o", "--output", type=str, default=None, help="Save JSON report")
    scan.add_argument("--html", type=str, default=None, dest="html_output")
    scan.add_argument("--sarif", type=str, default=None, dest="sarif_output")
    scan.add_argument("--policy", type=str, default=None)
    scan.add_argument("--max-size", type=float, default=2.0, metavar="MB")
    scan.add_argument("--skip", type=str, default=None, help="Analyzers to skip (comma-sep)")
    scan.add_argument("--workers", type=int, default=4)
    scan.add_argument("--no-history", action="store_true", help="Don't save to history DB")

    # dashboard
    dash = sub.add_parser("dashboard", help="Launch local web dashboard for scan history")
    dash.add_argument("--host", type=str, default="127.0.0.1")
    dash.add_argument("--port", type=int, default=9520)
    dash.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")

    # history
    hist = sub.add_parser("history", help="View or manage scan history from CLI")
    hist.add_argument("--last", type=int, default=10, help="How many recent scans to show")
    hist.add_argument("--delete", type=int, default=None, help="Delete a scan by ID")
    hist.add_argument("--stats", action="store_true", help="Show aggregate stats")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        if not Path(args.path).exists():
            print(f"Can't find: {args.path}", file=sys.stderr)
            sys.exit(1)

        skip_list = args.skip.split(",") if args.skip else None
        exit_code = scan_target(
            target=args.path,
            verbose=args.verbose,
            json_output=args.json_output,
            sarif_output=args.sarif_output,
            html_output=args.html_output,
            output_file=args.output,
            policy_path=args.policy,
            max_size_mb=args.max_size,
            skip_analyzers=skip_list,
            max_workers=args.workers,
            save_history=not args.no_history,
        )
        sys.exit(exit_code)

    elif args.command == "dashboard":
        from .ui.server import serve
        serve(host=args.host, port=args.port, open_browser=not args.no_browser)

    elif args.command == "history":
        from .history import get_scans, get_stats, delete_scan

        if args.delete is not None:
            ok = delete_scan(args.delete)
            print(f"Deleted scan #{args.delete}" if ok else f"Scan #{args.delete} not found")
            return

        if args.stats:
            s = get_stats()
            print(f"Total scans: {s['total_scans']}")
            print(f"Average risk: {s['avg_risk_score']}/10")
            if s['worst']:
                print(f"Worst: {s['worst']['target']} ({s['worst']['risk_score']}/10)")
            return

        scans = get_scans(limit=args.last)
        if not scans:
            print("No scan history yet. Run `reporeaver scan ./something`")
            return
        print(f"\n  Last {len(scans)} scans:\n")
        for s in scans:
            sev = s['max_sev'] or '?'
            target = (s.get('target') or '?').split('/')[-1]
            print(f"  #{s['id']:>4}  {sev:>8}  {s['risk_score']:>4}/10  "
                  f"{s['files_count'] or 0:>4} files  {target}")
        print()


if __name__ == "__main__":
    main()
