"""
demo_scenarios.py - runs the 7 required security scenarios automatically.

It copies sample_files/ into a throw-away "demo_sandbox/" folder, so your
original sample files are never touched.   Run:   python demo_scenarios.py
"""
import shutil
import time
from pathlib import Path

from fim.engine import FIMEngine
from fim.hasher import sha256_of_file
from fim.logging_setup import setup_logging
from fim.monitor import RealTimeMonitor
from fim.report import generate_report

ROOT = Path(__file__).resolve().parent
SANDBOX = ROOT / "demo_sandbox"
DATA = ROOT / "demo_data"
PASSWORD = "demo-admin-pass"


def banner(n, title):
    print(f"\n{'=' * 78}\nSCENARIO {n}: {title}\n{'=' * 78}")


def show_open(fim):
    open_events = fim.db.list_events(status="open")
    if not open_events:
        print("   (no open alerts)")
    for e in reversed(open_events):
        where = f"{Path(e['old_path']).name} -> {Path(e['path']).name}" if e["old_path"] else Path(e["path"]).name
        print(f"   #{e['id']} [{e['severity']}] {e['event_type']:<10} {where}")


def main():
    for folder in (SANDBOX, DATA):
        shutil.rmtree(folder, ignore_errors=True)
    shutil.copytree(ROOT / "sample_files", SANDBOX)
    setup_logging(DATA, console=False)          # logs go to demo_data/logs/fim_activity.log
    fim = FIMEngine(DATA)
    fim.set_admin_password(PASSWORD)
    target = SANDBOX / "documents" / "report.txt"

    banner(1, "Monitor a file/folder and establish its baseline SHA-256 hash")
    w = fim.add_watch(str(SANDBOX))
    print(f"   Monitoring folder: {w['path']}")
    print(f"   Baseline recorded for {w['baselined_files']} files:")
    for row in fim.db.all_baseline():
        print(f"     {Path(row['path']).name:<18} {row['sha256']}")
    print(f"   Verification scan -> {len(fim.scan().events)} alerts (files are intact)")

    banner(2, "Modify the contents of a monitored file")
    print(f"   Before: {sha256_of_file(target)[:32]}...")
    target.write_text(target.read_text() + "Patching completed on 100% of managed laptops. (edited by attacker)\n")
    print(f"   After : {sha256_of_file(target)[:32]}...   <- completely different")

    banner(3, "Detect the modification using SHA-256")
    res = fim.scan()
    show_open(fim)
    e = res.events[0]
    print(f"   baseline hash: {e['old_hash']}\n   current  hash: {e['new_hash']}")

    banner(4, "Delete a monitored file and detect the deletion")
    (SANDBOX / "configs" / "hosts_demo.txt").unlink()
    fim.scan()
    show_open(fim)

    banner(5, "Create a new file inside the monitored directory")
    (SANDBOX / "documents" / "backdoor.sh").write_text("#!/bin/sh\necho 'unauthorized script'\n")
    fim.scan()
    show_open(fim)

    banner("5b", "Bonus: rename detection (same content, new name)")
    (SANDBOX / "documents" / "notes.md").rename(SANDBOX / "documents" / "secret_plans.md")
    fim.scan()
    show_open(fim)

    banner(6, "Approve legitimate changes through a baseline update")
    try:
        fim.approve_all("wrong-password")
    except PermissionError as exc:
        print(f"   Attempt with WRONG password -> blocked: {exc}")
    legit = [ev for ev in fim.db.list_events(status="open") if ev["event_type"] in ("DELETED", "RENAMED")]
    for ev in legit:
        fim.approve(ev["id"], PASSWORD)
        print(f"   Approved #{ev['id']} ({ev['event_type']}) with the admin password")
    print("   Open alerts after approval:")
    show_open(fim)
    print(f"   Re-scan -> {len(fim.scan().events)} new alerts (baseline now matches the approved changes)")

    banner("6b", "Bonus: someone edits the BASELINE DATABASE to hide their tampering")
    import sqlite3
    victim = str(SANDBOX / "configs" / "app_config.ini")
    Path(victim).write_text("[server]\nhost = 0.0.0.0\n")
    forged = sha256_of_file(victim)
    con = sqlite3.connect(DATA / "fim.db")
    con.execute("UPDATE baseline SET sha256=? WHERE path=?", (forged, victim))
    con.commit()
    con.close()
    print("   Attacker changed app_config.ini AND overwrote its hash in the database...")
    fim.scan()
    show_open(fim)

    banner(7, "How the system records and displays tampering incidents")
    print("   --- Activity log (last lines of demo_data/logs/fim_activity.log) ---")
    for line in fim.log_tail(14).splitlines():
        print("   " + line)
    rep = generate_report(fim)
    print(f"\n   Report generated: {rep['markdown_path'].name}  and  {rep['html_path'].name}")
    print("   --- Report excerpt ---")
    for line in rep["markdown"].splitlines()[:14]:
        print("   " + line)

    banner("8", "Real-time detection with Watchdog (no manual scan)")
    fim.rebuild_baseline()
    monitor = RealTimeMonitor(fim.scanner, scan_interval=60, debounce=0.5)
    print(f"   Monitor started on {monitor.start()} location(s). Now editing a file...")
    (SANDBOX / "documents" / "report.txt").write_text("tampered in real time\n")
    for _ in range(40):
        time.sleep(0.25)
        hits = [e for e in fim.db.list_events(status="open") if e["source"] == "realtime"]
        if hits:
            break
    monitor.stop()
    for e in hits:
        print(f"   REAL-TIME ALERT -> {e['event_type']} {Path(e['path']).name} (source={e['source']})")
    if not hits:
        print("   (no real-time alert received)")

    print("\nDemo finished. Everything above was produced by the real engine.")


if __name__ == "__main__":
    main()
