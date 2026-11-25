"""Unit tests for Windows Event Log collector normalization, deduplication, and DB ingestion."""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from hulicap import db
from hulicap.collector import FileAccessDeduplicator, is_system_account, normalize, parse_event_xml
from hulicap.detector import pseudonymize_user


def _make_event_xml(event_id: int, record_id: int, system_time: str, data_fields: dict) -> str:
    data_xml = "\n".join(
        f'    <Data Name="{k}">{v}</Data>' for k, v in data_fields.items()
    )
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{system_time}" />
    <EventRecordID>{record_id}</EventRecordID>
    <Computer>WORKSTATION-01</Computer>
  </System>
  <EventData>
{data_xml}
  </EventData>
</Event>"""


class TestCollector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._db_path = os.path.join(cls._tmpdir.name, "test_collector.db")
        # Rebind db engine/SessionLocal to an isolated temp SQLite DB
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        db.engine = create_engine(f"sqlite:///{cls._db_path}", connect_args={"check_same_thread": False})
        db.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db.engine)
        db.init_db()

        cls.org_id = "org_test_win"
        cls.org_salt = "test_salt_123456"
        with db.get_session() as session:
            session.add(
                db.Organization(
                    org_id=cls.org_id,
                    name="Test Org",
                    industry="Tech",
                    plan_id="",
                    setup_completed=True,
                    status="active",
                    org_salt=cls.org_salt,
                )
            )
            session.commit()

        db.upsert_user_map(cls.org_id, "jdoe", cls.org_salt, role="engineer")
        db.upsert_resource_map(cls.org_id, r"C:\HuliCAP_TestData", sensitivity="high")

    @classmethod
    def tearDownClass(cls):
        db.engine.dispose()
        cls._tmpdir.cleanup()

    def test_system_account_filtering(self):
        for acct in ["WORKSTATION$", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-0", "-", ""]:
            self.assertTrue(is_system_account(acct), f"Expected system account: {acct}")
        self.assertFalse(is_system_account("jdoe"))

    def test_4624_interactive_only_and_field_name_parsing(self):
        # Interactive LogonType 2 kept, even if fields are in arbitrary order
        xml_interactive = _make_event_xml(
            4624,
            101,
            "2026-11-17T10:00:00.0000000Z",
            {"IpAddress": "10.0.0.5", "LogonType": "2", "TargetUserName": "jdoe"},
        )
        ev = normalize(xml_interactive, org_id=self.org_id, org_salt=self.org_salt)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["action"], "login")
        self.assertEqual(ev["outcome"], "success")
        self.assertEqual(ev["role"], "engineer")
        self.assertEqual(ev["device"], "managed")
        self.assertEqual(ev["source_ip"], "10.0.0.5")
        self.assertEqual(ev["bytes"], 0)
        self.assertEqual(ev["source"], "windows_event_log")
        self.assertEqual(ev["user_id"], pseudonymize_user("jdoe", salt=self.org_salt))

        # Timestamp matches local naive YYYY-MM-DD HH:MM:SS
        expected_local = (
            datetime(2026, 11, 17, 10, 0, 0, tzinfo=timezone.utc)
            .astimezone()
            .replace(tzinfo=None)
            .strftime("%Y-%m-%d %H:%M:%S")
        )
        self.assertEqual(ev["timestamp"], expected_local)

        # Network LogonType 3 ignored
        xml_network = _make_event_xml(
            4624,
            102,
            "2026-11-17T10:00:05.0000000Z",
            {"TargetUserName": "jdoe", "LogonType": "3", "IpAddress": "10.0.0.5"},
        )
        self.assertIsNone(normalize(xml_network, org_id=self.org_id, org_salt=self.org_salt))

    def test_4625_failed_logon_and_unknown_defaults(self):
        xml_fail = _make_event_xml(
            4625,
            103,
            "2026-11-17T10:01:00.0000000Z",
            {"TargetUserName": "alice", "LogonType": "2", "IpAddress": "-"},
        )
        ev = normalize(xml_fail, org_id=self.org_id, org_salt=self.org_salt)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["action"], "login")
        self.assertEqual(ev["outcome"], "denied")
        self.assertEqual(ev["role"], "unknown")
        self.assertEqual(ev["sensitivity"], "normal")
        self.assertEqual(ev["source_ip"], "127.0.0.1")

    def test_4663_access_mapping_and_dedup(self):
        xml_read_1 = _make_event_xml(
            4663,
            104,
            "2026-11-17T10:02:00.0000000Z",
            {
                "SubjectUserName": "jdoe",
                "ObjectName": r"C:\HuliCAP_TestData\secret.txt",
                "Accesses": "ReadData (or ListDirectory)",
            },
        )
        xml_read_2 = _make_event_xml(
            4663,
            105,
            "2026-11-17T10:02:01.0000000Z",
            {
                "SubjectUserName": "jdoe",
                "ObjectName": r"C:\HuliCAP_TestData\secret.txt",
                "Accesses": "ReadData (or ListDirectory)",
            },
        )
        xml_write = _make_event_xml(
            4663,
            106,
            "2026-11-17T10:02:03.0000000Z",
            {
                "SubjectUserName": "jdoe",
                "ObjectName": r"C:\HuliCAP_TestData\secret.txt",
                "Accesses": "WriteData (or AddFile)",
            },
        )
        xml_delete = _make_event_xml(
            4663,
            107,
            "2026-11-17T10:02:05.0000000Z",
            {
                "SubjectUserName": "jdoe",
                "ObjectName": r"C:\HuliCAP_TestData\secret.txt",
                "Accesses": "DELETE",
            },
        )

        ev1 = normalize(xml_read_1, org_id=self.org_id, org_salt=self.org_salt)
        ev2 = normalize(xml_read_2, org_id=self.org_id, org_salt=self.org_salt)
        ev_write = normalize(xml_write, org_id=self.org_id, org_salt=self.org_salt)
        ev_del = normalize(xml_delete, org_id=self.org_id, org_salt=self.org_salt)

        self.assertEqual(ev1["action"], "read")
        self.assertEqual(ev1["sensitivity"], "high")
        self.assertIsNone(ev_write)
        self.assertEqual(ev_del["action"], "delete")

        dedup = FileAccessDeduplicator(window_seconds=2)
        self.assertTrue(dedup.should_keep(ev1, 4663))
        self.assertFalse(dedup.should_keep(ev2, 4663))
        self.assertTrue(dedup.should_keep(ev_del, 4663))

    def test_ingest_event_and_record_id_persistence(self):
        xml_ok = _make_event_xml(
            4624,
            200,
            "2026-11-17T10:05:00.0000000Z",
            {"TargetUserName": "jdoe", "LogonType": "10", "IpAddress": "10.0.0.99"},
        )
        ev = normalize(xml_ok, org_id=self.org_id, org_salt=self.org_salt)
        saved_id = db.ingest_event(self.org_id, ev)
        self.assertEqual(saved_id, "win_200")

        with db.get_session() as session:
            row = session.query(db.Event).filter(db.Event.event_id == "win_200").first()
            self.assertIsNotNone(row)
            self.assertEqual(row.org_id, self.org_id)
            self.assertEqual(row.source, "windows_event_log")
            self.assertNotEqual(row.user_id, "jdoe")
            self.assertTrue(row.user_id.startswith("USER-"))

        self.assertEqual(db.get_last_record_id(self.org_id), 0)
        db.set_last_record_id(self.org_id, 200)
        self.assertEqual(db.get_last_record_id(self.org_id), 200)


if __name__ == "__main__":
    unittest.main()

