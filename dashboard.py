"""
dashboard.py - Streamlit security dashboard.

Run with:   streamlit run dashboard.py

Streamlit re-runs this whole script from top to bottom every time you click
something. That is why long-lived objects (the engine and the real-time monitor)
are created with @st.cache_resource: they are built ONCE and reused.
"""
import pandas as pd
import streamlit as st

from fim.engine import FIMEngine
from fim.logging_setup import setup_logging
from fim.monitor import RealTimeMonitor
from fim.report import generate_report

st.set_page_config(page_title="FIM Security Dashboard", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_engine() -> FIMEngine:
    setup_logging(console=False)
    return FIMEngine()


@st.cache_resource
def get_monitor(_engine: FIMEngine) -> RealTimeMonitor:
    return RealTimeMonitor(_engine.scanner)


fim = get_engine()
monitor = get_monitor(fim)
SEVERITY_BADGE = {"CRITICAL": "🟥 CRITICAL", "HIGH": "🟧 HIGH", "MEDIUM": "🟨 MEDIUM", "LOW": "🟩 LOW"}

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.title("🛡️ FIM Control Panel")

    st.subheader("1. Admin password")
    if not fim.admin_password_set():
        st.info("Create an admin password. It is required to approve baseline changes.")
        pw1 = st.text_input("New password (min 8 chars)", type="password", key="pw_new1")
        pw2 = st.text_input("Repeat password", type="password", key="pw_new2")
        if st.button("Save password"):
            if pw1 != pw2:
                st.error("Passwords do not match.")
            else:
                try:
                    fim.set_admin_password(pw1)
                    st.success("Admin password saved.")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
    else:
        st.text_input("Admin password (for approvals)", type="password", key="admin_pw")

    st.subheader("2. Monitored paths")
    new_path = st.text_input("File or folder to monitor", placeholder="/home/you/important_folder", key="new_path")
    if st.button("➕ Add & create baseline"):
        try:
            watch = fim.add_watch(new_path)
            if monitor.running:
                monitor.restart()
            st.success(f"Monitoring {watch['path']} ({watch['baselined_files']} file(s) baselined)")
        except ValueError as exc:
            st.error(str(exc))
    for watch in fim.watches():
        c1, c2 = st.columns([5, 1])
        c1.caption(f"{'📄' if watch['kind'] == 'file' else '📁'} {watch['path']}")
        if c2.button("✖", key=f"rm_{watch['path']}", help="Stop monitoring"):
            fim.remove_watch(watch["path"])
            if monitor.running:
                monitor.restart()
            st.rerun()

    st.subheader("3. Monitoring")
    if monitor.running:
        st.success("Real-time monitor: RUNNING")
        if st.button("⏹ Stop monitoring"):
            monitor.stop()
            st.rerun()
    else:
        st.warning("Real-time monitor: STOPPED")
        if st.button("▶ Start real-time monitoring"):
            if not fim.watches():
                st.error("Add a file or folder first.")
            else:
                monitor.start()
                st.rerun()
    if st.button("🔍 Scan now"):
        result = fim.scan(source="manual")
        st.toast(f"Scanned {result.files_scanned} files - {len(result.events)} new alert(s)")

st.title("File Integrity Monitoring & Tamper Detection")
tab_overview, tab_alerts, tab_log, tab_baseline, tab_report = st.tabs(
    ["📊 Overview", "🚨 Security Alerts", "📜 Activity Log", "🧱 Baseline Management", "📝 Report"])


def admin_password() -> str:
    return st.session_state.get("admin_pw", "")


# ----------------------------------------------------------------- overview
with tab_overview:
    @st.fragment(run_every=3)          # refreshes itself every 3 seconds
    def overview():
        s = fim.summary()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Monitored files", s["monitored_files"])
        c2.metric("Intact files", s["intact"])
        c3.metric("Open alerts", s["open_alerts"], delta=None)
        c4.metric("Incidents recorded", s["total_events"])
        st.caption(f"Last scan: {s['last_scan']}  |  Real-time monitor: "
                   f"{'running' if monitor.running else 'stopped'}")
        if s["open_alerts"] == 0:
            st.success("✅ All monitored files match the baseline.")
        else:
            st.error(f"⚠️ {s['open_alerts']} unresolved alert(s): " +
                     ", ".join(f"{n} {t}" for t, n in s["open_by_type"].items()))
        rows = fim.file_status()
        st.subheader("File integrity status")
        if rows:
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        else:
            st.info("Nothing monitored yet. Use the sidebar to add a file or folder.")
    overview()

# ------------------------------------------------------------------- alerts
with tab_alerts:
    @st.fragment(run_every=3)
    def alerts():
        open_events = fim.db.list_events(status="open")
        if not open_events:
            st.success("No open security alerts.")
            return
        if st.button("✅ Approve ALL open changes", key="approve_all"):
            try:
                n = fim.approve_all(admin_password())
                st.success(f"Baseline updated; {n} alert(s) closed.")
            except PermissionError as exc:
                st.error(str(exc))
        for ev in open_events:
            with st.container(border=True):
                left, right = st.columns([6, 1])
                where = f"{ev['old_path']}  →  {ev['path']}" if ev["old_path"] else ev["path"]
                left.markdown(f"**{SEVERITY_BADGE.get(ev['severity'], ev['severity'])}** &nbsp; "
                              f"`{ev['event_type']}` &nbsp; #{ev['id']} &nbsp; _{ev['timestamp']}_")
                left.code(where, language=None)
                if ev["old_hash"] or ev["new_hash"]:
                    left.caption(f"old: {(ev['old_hash'] or '-')[:24]}…   new: {(ev['new_hash'] or '-')[:24]}…")
                left.caption(f"{ev['details'] or ''}  (detected by: {ev['source']})")
                if right.button("Approve", key=f"approve_{ev['id']}"):
                    try:
                        fim.approve(ev["id"], admin_password())
                        st.rerun()
                    except PermissionError as exc:
                        st.error(str(exc))
    alerts()

# ---------------------------------------------------------------- activity
with tab_log:
    @st.fragment(run_every=5)
    def activity():
        events = fim.db.list_events()
        st.subheader("Incident history")
        if events:
            df = pd.DataFrame(events)[["id", "timestamp", "event_type", "severity", "path",
                                       "old_path", "status", "source"]]
            kinds = st.multiselect("Filter by type", sorted(df["event_type"].unique()),
                                   default=sorted(df["event_type"].unique()), key="filter_types")
            st.dataframe(df[df["event_type"].isin(kinds)], width="stretch", hide_index=True)
        else:
            st.info("No incidents recorded yet.")
        st.subheader("Activity log (last 100 lines)")
        st.code(fim.log_tail(100), language="log")
    activity()

# ---------------------------------------------------------------- baseline
with tab_baseline:
    st.subheader("Current baseline")
    base = fim.db.all_baseline()
    if base:
        st.dataframe(pd.DataFrame(base)[["path", "sha256", "size", "recorded_at"]],
                     width="stretch", hide_index=True)
    else:
        st.info("The baseline is empty.")
    st.markdown("**Rebuild baseline** - declares the *current* state of every monitored file as trusted "
                "and closes all open alerts. Only do this when you are sure nothing malicious happened.")
    confirm = st.checkbox("I understand and want to rebuild the baseline", key="confirm_rebuild")
    if st.button("🧱 Rebuild baseline", disabled=not confirm):
        if fim.verify_admin(admin_password()):
            st.success(f"Baseline rebuilt for {fim.rebuild_baseline()} file(s).")
        else:
            st.error("Wrong admin password - baseline NOT changed.")

# ------------------------------------------------------------------ report
with tab_report:
    st.write("Generate a summary of every tampering incident recorded so far.")
    if st.button("📝 Generate security report"):
        st.session_state["report"] = generate_report(fim)
    report = st.session_state.get("report")
    if report:
        st.success(f"Saved to {report['markdown_path']}")
        d1, d2 = st.columns(2)
        d1.download_button("⬇ Download Markdown", report["markdown"], report["markdown_path"].name, "text/markdown")
        d2.download_button("⬇ Download HTML", report["html"], report["html_path"].name, "text/html")
        st.markdown(report["markdown"])
