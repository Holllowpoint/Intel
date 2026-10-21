import os
import tempfile
import unittest

from database import SyllabusDB


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = SyllabusDB(self.tmp.name)

    def tearDown(self):
        self.db.close()
        os.unlink(self.tmp.name)

    def test_add_and_list_item(self):
        item_id = self.db.add_item("Physics past paper", "2026-10-21", "09:00", "assignment", "Physics")

        items = self.db.list_items()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["details"], "Physics past paper")
        self.assertEqual(items[0]["subject"], "Physics")

    def test_add_user_stores_hashed_password(self):
        self.db.add_user("teacher@example.com", "s3cret", "Teacher")

        role = self.db.get_user("teacher@example.com", "s3cret")

        self.assertEqual(role, "Teacher")

    def test_wrong_password_returns_none(self):
        self.db.add_user("student@example.com", "right", "Student")

        self.assertIsNone(self.db.get_user("student@example.com", "wrong"))

    def test_duplicate_user_is_ignored(self):
        self.db.add_user("a@example.com", "one", "Student")
        self.db.add_user("a@example.com", "two", "Student")

        self.assertEqual(len(self.db.conn.execute("SELECT * FROM users").fetchall()), 1)

    def test_update_item_rejects_unknown_column(self):
        item_id = self.db.add_item("Chemistry", "2026-10-22", "10:00", "topic", "Chemistry")

        with self.assertRaises(ValueError):
            self.db.update_item(item_id, not_a_column="oops")

    def test_update_item_changes_status(self):
        item_id = self.db.add_item("Biology", "2026-10-23", "11:00", "topic", "Biology")

        self.db.update_item(item_id, status="completed")

        self.assertEqual(self.db.get_item(item_id)["status"], "completed")

    def test_delete_item(self):
        item_id = self.db.add_item("Maths", "2026-10-24", "12:00", "topic", "Maths")
        self.db.delete_item(item_id)

        self.assertIsNone(self.db.get_item(item_id))


if __name__ == "__main__":
    unittest.main()
