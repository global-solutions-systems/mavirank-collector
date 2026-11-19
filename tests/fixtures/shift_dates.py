#!/usr/bin/env python3
"""Copy the fixture logs to OUT_DIR with timestamps shifted so that the newest line is "now".

Error log times stay local wall-clock times (+01:00); run the collector with ``timezone = +01:00``.

Used for the stack test (collector → ingest → dashboards): the fixtures have fixed dates
(2026-11-10/11) and would otherwise be older than the 30 day window at some point.

    python3 tests/fixtures/shift_dates.py /tmp/mavirank-logs [--end 2026-12-01T12:00:00Z]
"""
import argparse
import datetime as dt
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = ("access.log", "vhost_access.log", "error.log", "apache_error.log")
ACCESS = re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
NGINX = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
APACHE = re.compile(r"^\[([A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})(\.\d+)? (\d{4})\]")


def access_times(text):
    for m in ACCESS.finditer(text):
        yield dt.datetime.strptime(m.group(1) + " " + m.group(2), "%d/%b/%Y:%H:%M:%S %z")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--end", help="ISO time of the newest access line (default: now, UTC)")
    args = ap.parse_args()
    end = dt.datetime.fromisoformat(args.end.replace("Z", "+00:00")) if args.end else dt.datetime.now(dt.timezone.utc)
    # Error log fixtures carry local time without offset; they were written at +01:00.
    tz = dt.timezone(dt.timedelta(hours=1))
    stamps = []
    for name in FILES:
        with open(os.path.join(HERE, name), encoding="utf-8") as fh:
            for line in fh:
                stamps.extend(access_times(line))
                m = NGINX.match(line)
                if m:
                    stamps.append(dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=tz))
                m = APACHE.match(line)
                if m:
                    stamps.append(dt.datetime.strptime(m.group(1) + " " + m.group(3), "%a %b %d %H:%M:%S %Y").replace(tzinfo=tz))
    newest = max(stamps)
    shift = end - newest - dt.timedelta(minutes=1)
    os.makedirs(args.out_dir, exist_ok=True)

    def sub_access(m):
        t = dt.datetime.strptime(m.group(1) + " " + m.group(2), "%d/%b/%Y:%H:%M:%S %z") + shift
        return "[" + t.strftime("%d/%b/%Y:%H:%M:%S %z") + "]"

    def sub_nginx(m):
        return (dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S") + shift).strftime("%Y/%m/%d %H:%M:%S")

    def sub_apache(m):
        t = dt.datetime.strptime(m.group(1) + " " + m.group(3), "%a %b %d %H:%M:%S %Y") + shift
        return "[" + t.strftime("%a %b %d %H:%M:%S") + (m.group(2) or "") + " " + t.strftime("%Y") + "]"

    for name in FILES:
        with open(os.path.join(HERE, name), encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        out = []
        for line in lines:
            line = ACCESS.sub(sub_access, line, count=1)
            line = NGINX.sub(sub_nginx, line, count=1)
            line = APACHE.sub(sub_apache, line, count=1)
            out.append(line)
        with open(os.path.join(args.out_dir, name), "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    print(f"shifted by {shift}; files in {args.out_dir}")


if __name__ == "__main__":
    main()
