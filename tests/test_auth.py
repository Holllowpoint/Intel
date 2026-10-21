import unittest

from auth import hash_password, is_hashed_password, verify_password


class PasswordTests(unittest.TestCase):
    def test_hash_can_be_verified(self):
        stored_hash = hash_password("correct horse battery staple")

        self.assertTrue(is_hashed_password(stored_hash))
        self.assertTrue(verify_password("correct horse battery staple", stored_hash))
        self.assertFalse(verify_password("wrong password", stored_hash))

    def test_same_password_gets_different_salts(self):
        first_hash = hash_password("same password")
        second_hash = hash_password("same password")

        self.assertNotEqual(first_hash, second_hash)


if __name__ == "__main__":
    unittest.main()