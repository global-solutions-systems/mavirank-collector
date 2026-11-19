import datetime as dt
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Fixture logs cover 2026-11-10/11; all tests run "at" this moment.
NOW = dt.datetime(2026, 11, 12, 0, 0, 0, tzinfo=dt.timezone.utc)
TOKEN = "mvrk_log_TESTTOKENTESTTOKENTESTTOKENTESTTOKEN0000000"


def fixture(name):
    return os.path.join(FIXTURES, name)


def fixture_lines(name):
    with open(fixture(name), encoding="utf-8") as fh:
        return [line.rstrip("\n") for line in fh]
