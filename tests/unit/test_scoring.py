import datetime
import json
import unittest
from unittest.mock import patch
import fakeredis

from store import Store
from scoring import get_score, get_interests

from tests.test_utils import cases


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.context = {}
        self.headers = {}
        self.store = self._init_store()

    @patch("redis.StrictRedis", return_value=fakeredis.FakeStrictRedis())
    def _init_store(self, mock_redis):
        return Store()

    @cases(
        [
            ({"phone": "79175002040", "email": "stupnikov@otus.ru"}, 3.0),
            (
                {
                    "phone": "79175002040",
                    "email": "stupnikov@otus.ru",
                    "gender": 1,
                    "birthday": datetime.date(2000, 1, 1),
                    "first_name": "a",
                    "last_name": "b",
                },
                5.0,
            ),
            (
                {
                    "phone": "79175002040",
                    "email": "stupnikov@otus.ru",
                    "gender": 1,
                    "first_name": "a",
                },
                3.0,
            ),
        ]
    )
    def test_get_score(self, data, expected):
        assert get_score(self.store, **data) == expected

    @cases(
        [
            ({"cid": "1"}, ["cars", "pets"]),
            ({"cid": "2"}, ["cars", "pets", "travel"]),
        ]
    )
    def test_get_interests(self, data, expected):
        cid = data.get("cid")
        self.store.cache_set(f"i:{cid}", json.dumps(expected), 60 * 60)
        self.assertEqual(get_interests(self.store, cid), expected)


if __name__ == "__main__":
    unittest.main()
