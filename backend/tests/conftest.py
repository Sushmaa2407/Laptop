import os

# Database tests run only against a dedicated *_test database.
_test_url = os.environ.get("TEST_DATABASE_URL")
if _test_url:
    assert _test_url.rsplit("/", 1)[-1].endswith("_test"), "TEST_DATABASE_URL must point at a *_test database"
    os.environ["DATABASE_URL"] = _test_url
os.environ["SHIELD_DB_NULLPOOL"] = "1"
