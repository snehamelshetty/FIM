"""
cli.py - command-line interface.

Examples (run from the project folder):
    python cli.py set-password
    python cli.py add sample_files
    python cli.py scan
    python cli.py watch              # real-time monitoring, Ctrl+C to stop
    python cli.py events --open
    python cli.py approve 3
    python cli.py report
"""
import argparse
import getpass
import sys
import time

from fim.engine import FIMEngine
from fim.logging_setup import setup_logging
from fim.monitor import RealTimeMonitor
from fim.report import generate_report


def ask_password(prompt="Admin password: "):
    return getpass.getpass(prompt)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-password", help="create/change the admin password")
    p = sub.add_parser("add", help="monitor a file or folder (creates its baseline)")
    p.add_argument("path")
    p = sub.add_parser("remove", help="stop monitoring a path")
    p.add_argument("path")
    sub.add_parser("list", help="show monitored paths and file status")
    sub.add_parser("scan", help="compare files with the baseline once")
    sub.add_parser("watch", help="real-time monitoring (Ctrl+C to stop)")
    p = sub.add_parser("events", help="show recorded incidents")
    p.add_argument("--open", action="store_true", help="only unresolved ones")
    p = sub.add_parser("approve", help="accept a change as legitimate (admin password)")
    p.add_argument("event_id", help="event number, or 'all'")
    sub.add_parser("rebuild-baseline", help="trust the current state of everything (admin password)")
    sub.add_parser("report", help="generate Markdown + HTML security report")
    args = parser.parse_args(argv)

    setup_logging(console=True)
    fim = FIMEngine()

    try:
        if args.cmd == "set-password":
            current = ask_password("Current password: ") if fim.admin_password_set() else None
            new = ask_password("New password: ")
            if new != ask_password("Repeat new password: "):
                print("Passwords do not match.")
                return 1
            fim.set_admin_password(new, current)
            print("Admin password saved.")

        elif args.cmd == "add":
            w = fim.add_watch(args.path)
            print(f"Now monitoring {w['path']} - baseline recorded for {w['baselined_files']} file(s).")

        elif args.cmd == "remove":
            fim.remove_watch(args.path)
            print("Removed.")

        elif args.cmd == "list":
            for w in fim.watches():
                print(f"[{w['kind']}] {w['path']}")
            for row in fim.file_status():
                print(f"  {row['Status']:<28} {row['File']}")

        elif args.cmd == "scan":
            res = fim.scan()
            print(f"Scanned {res.files_scanned} files in {res.duration:.2f}s - {len(res.events)} new alert(s).")

        elif args.cmd == "watch":
            monitor = RealTimeMonitor(fim.scanner)
            n = monitor.start()
            print(f"Watching {n} location(s). Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                monitor.stop()

        elif args.cmd == "events":
            for e in reversed(fim.db.list_events(status="open" if args.open else None)):
                where = f"{e['old_path']} -> {e['path']}" if e["old_path"] else e["path"]
                print(f"#{e['id']:<3} {e['timestamp']} {e['severity']:<8} {e['event_type']:<17} {e['status']:<9} {where}")

        elif args.cmd == "approve":
            pw = ask_password()
            n = fim.approve_all(pw) if args.event_id == "all" else fim.approve(int(args.event_id), pw)
            print(f"Baseline updated; {n} alert(s) closed.")

        elif args.cmd == "rebuild-baseline":
            if not fim.verify_admin(ask_password()):
                print("Wrong admin password.")
                return 1
            print(f"Baseline rebuilt for {fim.rebuild_baseline()} file(s).")

        elif args.cmd == "report":
            rep = generate_report(fim)
            print(f"Report written:\n  {rep['markdown_path']}\n  {rep['html_path']}")
    except (ValueError, PermissionError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
