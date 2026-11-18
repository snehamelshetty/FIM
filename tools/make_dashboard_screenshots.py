"""
OPTIONAL helper: drives the real dashboard in a headless browser and saves
screenshots of the whole test story into screenshots/.

    pip install playwright && python -m playwright install chromium
    python tools/make_dashboard_screenshots.py
"""
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "screenshots"
SANDBOX = ROOT / "demo_sandbox_ui"
DATA = ROOT / "demo_data_ui"
PORT = 8599
URL = f"http://localhost:{PORT}"
PASSWORD = "admin-pass-123"


def wait_for_server():
    for _ in range(60):
        try:
            urllib.request.urlopen(URL, timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("Streamlit did not start")


def main():
    for folder in (SANDBOX, DATA):
        shutil.rmtree(folder, ignore_errors=True)
    shutil.copytree(ROOT / "sample_files", SANDBOX)
    SHOTS.mkdir(exist_ok=True)

    env = dict(os.environ, FIM_DATA_DIR=str(DATA))
    server = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "dashboard.py"), "--server.port", str(PORT),
         "--server.headless", "true", "--browser.gatherUsageStats", "false"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for_server()
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1500, "height": 950})
            page.goto(URL)
            page.get_by_label("New password (min 8 chars)").fill(PASSWORD)
            page.get_by_label("New password (min 8 chars)").press("Enter")
            page.get_by_label("Repeat password").fill(PASSWORD)
            page.get_by_label("Repeat password").press("Enter")
            page.get_by_role("button", name="Save password").click()
            page.get_by_label("Admin password (for approvals)").fill(PASSWORD)
            page.get_by_label("Admin password (for approvals)").press("Enter")
            page.get_by_label("File or folder to monitor").fill(str(SANDBOX))
            page.get_by_label("File or folder to monitor").press("Enter")
            page.get_by_role("button", name=re.compile("Add & create baseline")).click()
            page.wait_for_timeout(1500)
            page.get_by_role("button", name=re.compile("Start real-time monitoring")).click()
            page.wait_for_timeout(2500)
            page.screenshot(path=SHOTS / "01_baseline_and_intact_status.png")

            # Scenario 2/3: modify a file -> detected
            target = SANDBOX / "documents" / "report.txt"
            target.write_text(target.read_text() + "Edited by an attacker!\n")
            page.wait_for_timeout(6000)
            page.screenshot(path=SHOTS / "02_modification_detected_overview.png")
            page.get_by_role("tab", name=re.compile("Security Alerts")).click()
            page.wait_for_timeout(800)
            page.screenshot(path=SHOTS / "03_modification_alert_with_hashes.png")

            # Scenario 4/5: delete one file, create another
            (SANDBOX / "configs" / "hosts_demo.txt").unlink()
            (SANDBOX / "documents" / "backdoor.sh").write_text("#!/bin/sh\necho unauthorized\n")
            page.wait_for_timeout(6000)
            page.screenshot(path=SHOTS / "04_delete_and_create_alerts.png", full_page=True)

            # Scenario 6: approve the legitimate change (deletion) via baseline update
            page.get_by_role("button", name="Approve", exact=True).nth(1).click()
            page.wait_for_timeout(2500)
            page.screenshot(path=SHOTS / "05_approved_change_alert_closed.png", full_page=True)

            # Overview after approval
            page.get_by_role("tab", name=re.compile("Overview")).click()
            page.wait_for_timeout(800)
            page.screenshot(path=SHOTS / "06_overview_after_approval.png", full_page=True)

            # Scenario 7: activity log + report
            page.get_by_role("tab", name=re.compile("Activity Log")).click()
            page.wait_for_timeout(1200)
            page.screenshot(path=SHOTS / "07_activity_log_and_incident_history.png", full_page=True)
            page.get_by_role("tab", name=re.compile("Report")).click()
            page.get_by_role("button", name=re.compile("Generate security report")).click()
            page.wait_for_timeout(1500)
            page.screenshot(path=SHOTS / "08_security_report.png", full_page=True)
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    print("Screenshots saved to", SHOTS)


if __name__ == "__main__":
    main()
