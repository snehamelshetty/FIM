"""
Automated tests. Run with:   python -m unittest -v
Each test builds a throw-away folder, so nothing real is touched.
"""
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fim.engine import FIMEngine
from fim.hasher import HashError, sha256_of_file, sha256_of_text
from fim.logging_setup import setup_logging
from fim.report import generate_report
from fim.validators import validate_watch_path


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.data = self.tmp / "data"
        self.watch = self.tmp / "watched"
        self.watch.mkdir()
        (self.watch / "a.txt").write_text("alpha")
        (self.watch / "b.txt").write_text("bravo")
        setup_logging(self.data, console=False)
        self.fim = FIMEngine(self.data)
        self.fim.add_watch(str(self.watch))
        self.fim.set_admin_password("correct-horse")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def types(self, result):
        return sorted(e["event_type"] for e in result.events)


class HashTests(BaseCase):
    def test_known_vector(self):
        # Official SHA-256 of "abc"
        self.assertEqual(sha256_of_text("abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_file_hash_matches_text_hash(self):
        self.assertEqual(sha256_of_file(self.watch / "a.txt"), sha256_of_text("alpha"))

    def test_one_character_changes_hash(self):
        self.assertNotEqual(sha256_of_text("alpha"), sha256_of_text("alphA"))

    def test_missing_file_raises(self):
        with self.assertRaises(HashError):
            sha256_of_file(self.watch / "nope.txt")


class DetectionTests(BaseCase):
    def test_clean_scan_has_no_events(self):
        self.assertEqual(self.fim.scan().events, [])

    def test_modification(self):
        (self.watch / "a.txt").write_text("alpha-HACKED")
        res = self.fim.scan()
        self.assertEqual(self.types(res), ["MODIFIED"])
        self.assertEqual(res.events[0]["severity"], "HIGH")

    def test_deletion(self):
        (self.watch / "b.txt").unlink()
        self.assertEqual(self.types(self.fim.scan()), ["DELETED"])

    def test_creation(self):
        (self.watch / "evil.sh").write_text("rm -rf /")
        self.assertEqual(self.types(self.fim.scan()), ["CREATED"])

    def test_rename(self):
        (self.watch / "a.txt").rename(self.watch / "a_renamed.txt")
        res = self.fim.scan()
        self.assertEqual(self.types(res), ["RENAMED"])
        self.assertTrue(res.events[0]["old_path"].endswith("a.txt"))

    def test_touch_without_content_change_is_ignored(self):
        os.utime(self.watch / "a.txt", (1_000_000_000, 1_000_000_000))
        self.assertEqual(self.fim.scan().events, [])

    def test_same_alert_not_duplicated(self):
        (self.watch / "a.txt").write_text("changed")
        self.fim.scan()
        self.assertEqual(self.fim.scan().events, [])
        self.assertEqual(len(self.fim.db.list_events(status="open")), 1)

    def test_revert_auto_closes_alert(self):
        (self.watch / "a.txt").write_text("changed")
        self.fim.scan()
        (self.watch / "a.txt").write_text("alpha")
        self.fim.scan()
        self.assertEqual(self.fim.db.list_events(status="open"), [])
        self.assertEqual(len(self.fim.db.list_events(status="reverted")), 1)

    def test_subfolder_files_are_monitored(self):
        sub = self.watch / "deep" / "er"
        sub.mkdir(parents=True)
        (sub / "x.txt").write_text("x")
        self.assertEqual(self.types(self.fim.scan()), ["CREATED"])


class BaselineTests(BaseCase):
    def test_approve_modification_updates_baseline(self):
        (self.watch / "a.txt").write_text("legit change")
        ev = self.fim.scan().events[0]
        self.fim.approve(ev["id"], "correct-horse")
        self.assertEqual(self.fim.scan().events, [])
        self.assertEqual(self.fim.db.list_events(status="approved")[0]["id"], ev["id"])

    def test_approve_deletion_and_creation(self):
        (self.watch / "b.txt").unlink()
        (self.watch / "new.txt").write_text("new")
        self.fim.scan()
        self.assertEqual(self.fim.approve_all("correct-horse"), 2)
        self.assertEqual(self.fim.scan().events, [])

    def test_wrong_password_blocks_approval(self):
        (self.watch / "a.txt").write_text("changed")
        ev = self.fim.scan().events[0]
        with self.assertRaises(PermissionError):
            self.fim.approve(ev["id"], "wrong-password")
        self.assertEqual(len(self.fim.db.list_events(status="open")), 1)

    def test_password_too_short(self):
        with self.assertRaises(ValueError):
            self.fim.set_admin_password("short")

    def test_baseline_database_tampering_is_detected(self):
        # Attacker edits the file AND rewrites the baseline hash to hide it.
        (self.watch / "a.txt").write_text("evil")
        new_hash = sha256_of_text("evil")
        con = sqlite3.connect(self.data / "fim.db")
        con.execute("UPDATE baseline SET sha256=? WHERE path LIKE '%a.txt'", (new_hash,))
        con.commit()
        con.close()
        res = self.fim.scan()
        self.assertIn("BASELINE_TAMPERED", self.types(res))
        self.assertEqual([e["severity"] for e in res.events if e["event_type"] == "BASELINE_TAMPERED"], ["CRITICAL"])

    def test_rebuild_baseline_closes_alerts(self):
        (self.watch / "a.txt").write_text("changed")
        self.fim.scan()
        self.fim.rebuild_baseline()
        self.assertEqual(self.fim.db.list_events(status="open"), [])
        self.assertEqual(self.fim.scan().events, [])


class ValidationAndReportTests(BaseCase):
    def test_validation(self):
        for bad in ["", "   ", "/definitely/not/here", "/"]:
            with self.assertRaises(ValueError):
                validate_watch_path(bad, self.data)
        with self.assertRaises(ValueError):
            validate_watch_path(str(self.data), self.data)       # FIM's own folder
        self.assertEqual(validate_watch_path(str(self.watch), self.data), self.watch.resolve())

    def test_fim_data_folder_is_never_scanned(self):
        self.fim.add_watch(str(self.tmp / "watched"))
        files = list(self.fim.scanner.iter_files())
        self.assertFalse(any(str(self.data) in f for f in files))

    def test_report_files_created(self):
        (self.watch / "a.txt").write_text("changed")
        self.fim.scan()
        rep = generate_report(self.fim)
        self.assertTrue(rep["markdown_path"].exists() and rep["html_path"].exists())
        self.assertIn("MODIFIED", rep["markdown"])
        self.assertIn("ATTENTION", rep["markdown"])


class DashboardSmokeTest(unittest.TestCase):
    """Loads the Streamlit page headlessly and clicks through the main flow."""

    def test_dashboard_flow(self):
        from streamlit.testing.v1 import AppTest
        tmp = Path(tempfile.mkdtemp())
        (tmp / "w").mkdir()
        (tmp / "w" / "f.txt").write_text("hello")
        from fim import config
        original_data_dir = config.DATA_DIR
        config.DATA_DIR = (tmp / "data").resolve()
        try:
            at = AppTest.from_file(str(Path(__file__).resolve().parent.parent / "dashboard.py"),
                                   default_timeout=30).run()
            self.assertFalse(at.exception)
            at.text_input(key="pw_new1").set_value("admin-pass-1")
            at.text_input(key="pw_new2").set_value("admin-pass-1")
            [b for b in at.button if b.label == "Save password"][0].click()
            at.run()
            at.text_input(key="new_path").set_value(str(tmp / "w"))
            [b for b in at.button if "Add" in b.label][0].click()
            at.run()
            (tmp / "w" / "f.txt").write_text("tampered")
            [b for b in at.button if "Scan now" in b.label][0].click()
            at.run()
            self.assertFalse(at.exception)
            self.assertTrue(any("1 MODIFIED" in e.value for e in at.error))
        finally:
            config.DATA_DIR = original_data_dir
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()